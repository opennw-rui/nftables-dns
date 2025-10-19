#!/usr/bin/env python3
from datetime import datetime, timedelta
import signal
from pathlib import Path
import configparser
from time import sleep
from typing import List, Optional
import gc
import resource
import sys

import argparse
import dns.resolver
import logging

import subprocess
from pydantic import IPvAnyAddress

import entry

config = configparser.ConfigParser(interpolation=None)

values = []
stop = False
# 优化日志配置，减少格式处理开销
logging.basicConfig(
    format='%(asctime)s %(levelname)s:%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logging.getLogger().setLevel(logging.INFO)

# 内存监控配置
MEMORY_LIMIT_MB = 100  # 内存使用上限
MEMORY_CHECK_INTERVAL = 20  # 内存检查间隔（秒）

def memory_usage_mb():
    """获取当前内存使用量（MB）"""
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

def check_memory_usage():
    """检查内存使用情况，必要时进行清理"""
    current_memory = memory_usage_mb()
    if current_memory > MEMORY_LIMIT_MB:
        logging.warning(f"Memory usage high: {current_memory:.2f}MB, triggering garbage collection")
        gc.collect()
        logging.info(f"After GC: {memory_usage_mb():.2f}MB")

def read_config():
    if args.config_file and Path(args.config_file).is_file():
        logging.info(f'Reading config file : {Path(args.config_file).absolute()}')
        config.read(Path(args.config_file))
    else:
        logging.error('Config file not found, Exiting...')
        sys.exit(1)  # 使用sys.exit代替exit
    
    if config.has_option('GLOBAL', 'include_config_dir'):
        config_dir = Path(config['GLOBAL']['include_config_dir'])
        if not config_dir.is_dir():
            logging.error(f"Config directory is not a directory, Ignoring...")
        else:
            logging.info('Only config file with prefix .conf is read')
            logging.info(f"Reading config directory : {config_dir.absolute()}")
            list_config = list(config_dir.glob("*.conf"))
            [logging.info(f"   {i}") for i in list_config]
            config.read(list_config)
    
    logging.info("# Parsing the configuration")
    if args.verbose or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('verbose')):
        logging.getLogger().setLevel(logging.DEBUG)

    global values
    values = []  # 确保清空values列表
    
    for section in config.sections():
        if section != 'GLOBAL' and config[section].getboolean('enable', fallback=False):
            domains = config[section]["domains"].split(',')
            for fqdn in domains:
                fqdn = fqdn.strip()
                if not fqdn:
                    continue
                    
                if config[section]["family"] in ['ip', 'ip6', 'inet']:
                    family = config[section]["family"]
                else:
                    logging.error(f"Configuration error, family of {fqdn} not: ip, ip6 or inet")
                    sys.exit(1)
                
                table = config[section].get('table', fallback='filter')
                set_name = config[section]['set_name']
                
                res = run_command(f"nft list set {family} {table} {set_name}")
                typeof = 4
                if not (args.dry_run or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('dry_run', fallback=False))):
                    if "type ipv4_addr" in res:
                        typeof = 4
                        logging.debug(f"set {set_name} well defined in ipv4_addr family")
                    elif "type ipv6_addr" in res:
                        typeof = 6
                        logging.debug(f"set {set_name} well defined in ipv6_addr family")
                    else:
                        logging.error(f"Type of the {set_name} set not defined to \"ipv4_addr\" or \"ipv6_addr\" into the nftables set. Only these types are allowed.")
                        sys.exit(1)
                else:
                    logging.info('The dry_run option force the typeof to "ipv4" since no commands are executed to check that')
                
                result = entry.ModelEntry(
                    set_name=set_name,
                    family=family,
                    table=table,
                    typeof=typeof,
                    fqdn=fqdn,
                    ip_list=None,
                    ttl=None,
                    next_update=None
                )
                values.append(result)
                logging.debug(result)
    
    if len(values) == 0:
        logging.error("No entries configured, I've nothing to do, Exiting...")
        sys.exit(1)

    logging.info("# End of Parsing")

def update_dns() -> None:
    global values
    # 缓存解析器实例，避免重复创建
    if config.has_option('GLOBAL', 'custom_resolver'):
        resolver = dns.resolver.make_resolver_at(config['GLOBAL']['custom_resolver'])
    else:
        resolver = dns.resolver.Resolver()
    
    max_ttl = config['GLOBAL'].getint('max_ttl', fallback=86400)
    min_ttl = config['GLOBAL'].getint('min_ttl', fallback=300)

    current_time = datetime.now()
    updated_values = []
    
    for entry_item in values:
        # 使用局部变量减少属性访问
        next_update = entry_item.next_update
        if next_update and next_update > current_time:
            updated_values.append(entry_item)
            continue
            
        old_ip_list = entry_item.ip_list
        logging.debug(f"Update for {entry_item} in progress...")
        
        try:
            rd_type = "A" if entry_item.typeof == 4 else "AAAA"
            answer = resolver.resolve(entry_item.fqdn, rdtype=rd_type, lifetime=10)  # 设置超时
            
            # 使用列表推导式，更高效
            new_ip_list = sorted(item.address for item in answer.rrset)
            entry_item.ip_list = new_ip_list
            entry_item.ttl = answer.rrset.ttl
            
            # 计算下次更新时间
            ttl_adjusted = max(min(entry_item.ttl, max_ttl) + 1, min_ttl)
            entry_item.next_update = current_time + timedelta(seconds=ttl_adjusted + 1)
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
            logging.warning(f"Failed to resolve FQDN '{entry_item.fqdn}' for set '{entry_item.set_name}': {e}")
            # 保持条目但标记为需要稍后重试
            if entry_item.next_update is None:
                entry_item.next_update = current_time + timedelta(seconds=min_ttl)
            updated_values.append(entry_item)
            continue
        
        logging.debug(entry_item)
        
        if old_ip_list != new_ip_list:
            logging.info(f"Updating the IPv{entry_item.typeof} for {entry_item.fqdn} with {new_ip_list}")
            apply_config_entry(entry_item, old_ip_list=old_ip_list)
        else:
            logging.debug(f"Nothing has changed for the IPv{entry_item.typeof} for {entry_item.fqdn}")
        
        updated_values.append(entry_item)
    
    values = updated_values

def get_next_run_timer() -> datetime:
    """获取下次运行时间，优化性能"""
    if not values:
        return datetime.now() + timedelta(seconds=300)  # 默认5分钟
    
    # 使用生成器表达式减少内存使用
    next_updates = (entry_item.next_update for entry_item in values if entry_item.next_update)
    valid_updates = [nu for nu in next_updates if nu is not None]
    
    if not valid_updates:
        return datetime.now() + timedelta(seconds=300)
    
    return min(valid_updates)

def safe_delete_element(one_entry: entry.ModelEntry, ip_list: List[IPvAnyAddress]) -> bool:
    """安全删除元素，如果失败则先添加再删除"""
    if not ip_list:
        return True
        
    ip_str = ', '.join(str(ip) for ip in ip_list)
    delete_cmd = f"nft delete element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{ip_str}}}"
    
    try:
        run_command(delete_cmd)
        return True
    except subprocess.CalledProcessError as e:
        logging.warning(f"Delete failed for set {one_entry.set_name}, attempting recovery: {e}")
        
        # 先添加所有IP
        add_cmd = f"nft add element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{ip_str}}}"
        try:
            run_command(add_cmd)
            logging.info(f"Successfully re-added IPs to set {one_entry.set_name}")
        except subprocess.CalledProcessError as add_error:
            logging.error(f"Failed to re-add IPs to set {one_entry.set_name}: {add_error}")
            return False
        
        # 然后再删除
        try:
            run_command(delete_cmd)
            logging.info(f"Successfully deleted IPs from set {one_entry.set_name} after recovery")
            return True
        except subprocess.CalledProcessError as final_error:
            logging.error(f"Failed to delete IPs from set {one_entry.set_name} even after recovery: {final_error}")
            return False

def apply_config_entry(one_entry: entry.ModelEntry, old_ip_list: List[IPvAnyAddress] | None) -> None:
    """应用配置条目，优化命令执行"""
    if old_ip_list:
        # 使用安全删除
        if not safe_delete_element(one_entry, old_ip_list):
            logging.error(f"Failed to delete old IPs for set {one_entry.set_name}")

    if one_entry.ip_list:
        # 批量添加新IP，减少nft命令调用
        ip_str = ', '.join(str(ip) for ip in one_entry.ip_list)
        run_command(f"nft add element {one_entry.family} {one_entry.table} {one_entry.set_name} {{{ip_str}}}")

def remove_config_entries():
    """清理所有条目，优化执行"""
    logging.info("Cleaning all entries")
    for entry_item in values:
        if entry_item.ip_list:
            # 使用安全删除
            if not safe_delete_element(entry_item, entry_item.ip_list):
                logging.error(f"Failed to delete IPs for set {entry_item.set_name} during cleanup")

def run_command(cmd: str) -> str:
    """运行命令，添加超时和错误处理优化"""
    logging.debug(f"Command to run : {cmd}")
    
    if args.dry_run or (config.has_option('GLOBAL', 'dry_run') and config['GLOBAL'].getboolean('dry_run', fallback=False)):
        logging.debug("Dry-run detected, logging only, the previous command isn't executed")
        return "dry-run-output"
    
    try:
        # 添加超时防止命令挂起
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True, 
            shell=True,
            timeout=30  # 30秒超时
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {e}")
        logging.error(f"stdout: {e.stdout}")
        logging.error(f"stderr: {e.stderr}")
        # 抛出异常让上层处理
        raise
    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {cmd}")
        raise
    except FileNotFoundError:
        logging.error("The nft command isn't found. Run with --dry-run to avoid nftable change attempts")
        sys.exit(1)

def run_loop():
    """优化主循环，减少CPU占用"""
    last_memory_check = datetime.now()
    
    while not stop:
        update_dns()
        
        # 定期检查内存使用情况
        current_time = datetime.now()
        if (current_time - last_memory_check).seconds >= MEMORY_CHECK_INTERVAL:
            check_memory_usage()
            last_memory_check = current_time
        
        next_run = get_next_run_timer()
        sleep_seconds = max(1, (next_run - current_time).total_seconds())
        
        logging.info(f"Sleeping for {sleep_seconds:.0f}s")
        
        # 使用单次sleep代替循环sleep，减少CPU占用
        # 但为了能够及时响应停止信号，将长睡眠分解为多个短睡眠
        sleep_interval = min(5, sleep_seconds)  # 最多睡5秒就检查一次
        remaining_sleep = sleep_seconds
        
        while remaining_sleep > 0 and not stop:
            actual_sleep = min(sleep_interval, remaining_sleep)
            sleep(actual_sleep)
            remaining_sleep -= actual_sleep
    
    # 退出前清理
    if not args.dry_run:
        remove_config_entries()

def main():
    """主函数，添加初始化优化"""
    try:
        read_config()
        # 初始内存检查
        check_memory_usage()
        run_loop()
    except KeyboardInterrupt:
        logging.info("Program interrupted by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

def handler(signum, frame):
    """信号处理函数"""
    logging.warning(f"{signal.Signals(signum).name}({signum}) signal received. Exiting")
    global stop
    stop = True

if __name__ == '__main__':
    try:
        # 设置内存限制为100MB
        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        new_limit = MEMORY_LIMIT_MB * 1024 * 1024  # 转换为bytes
        resource.setrlimit(resource.RLIMIT_AS, (new_limit, hard))
    except (ValueError, resource.error) as e:
        logging.warning(f"Could not set memory limit: {e}")
    
    parser = argparse.ArgumentParser(description='DNS plugin for NFTables')
    parser.add_argument('-c', '--config', type=str, dest='config_file', default='/etc/nft-dns.conf', help='Config file')
    parser.add_argument('-t', '--dry-run', dest='dry_run', action="store_true", help="Test Mode, dry-run will not run any nftables command, useful with verbose mode")
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help="Verbose logging mode, will log all actions")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler)  # For simple CTRL+C
    signal.signal(signal.SIGTERM, handler)  # For Systemd stop
    main()

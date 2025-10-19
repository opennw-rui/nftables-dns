#!/usr/bin/env python3
from datetime import datetime, timedelta
import signal
from pathlib import Path
import configparser
from time import sleep
import gc
import resource
import sys
import argparse
import dns.resolver
import logging
import subprocess

import entry

class DNSNFTManager:
    def __init__(self):
        self.config = configparser.ConfigParser(interpolation=None)
        self.entries = []
        self.stop = False
        self.args = self.parse_args()
        self.setup_logging()
        self.setup_memory_limit()
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def parse_args(self):
        parser = argparse.ArgumentParser(description='DNS plugin for NFTables')
        parser.add_argument('-c', '--config', type=str, dest='config_file', 
                          default='/etc/nft-dns.conf', help='Config file')
        parser.add_argument('-t', '--dry-run', dest='dry_run', action="store_true",
                          help="Test Mode, dry-run will not run any nftables command")
        parser.add_argument('-v', '--verbose', dest='verbose', action="store_true",
                          help="Verbose logging mode")
        return parser.parse_args()

    def setup_logging(self):
        level = logging.DEBUG if self.args.verbose else logging.INFO
        logging.basicConfig(
            format='%(asctime)s %(levelname)s:%(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            level=level
        )

    def setup_memory_limit(self):
        try:
            MEMORY_LIMIT_MB = 100
            new_limit = MEMORY_LIMIT_MB * 1024 * 1024
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (new_limit, hard))
        except (ValueError, resource.error) as e:
            logging.warning(f"Could not set memory limit: {e}")

    def signal_handler(self, signum, frame):
        logging.warning(f"{signal.Signals(signum).name}({signum}) signal received. Exiting")
        self.stop = True

    def read_config_files(self):
        """读取主配置文件和包含的配置文件"""
        config_file = Path(self.args.config_file)
        if not config_file.is_file():
            logging.error('Config file not found, Exiting...')
            sys.exit(1)

        logging.info(f'Reading config file: {config_file.absolute()}')
        self.config.read(config_file)

        # 读取包含的配置文件
        if self.config.has_option('GLOBAL', 'include_config_dir'):
            config_dir = Path(self.config['GLOBAL']['include_config_dir'])
            if config_dir.is_dir():
                config_files = list(config_dir.glob("*.conf"))
                logging.info(f"Reading config directory: {config_dir.absolute()}")
                self.config.read(config_files)

    def create_entry(self, section, fqdn):
        """创建配置条目"""
        family = self.config[section]["family"]
        if family not in ['ip', 'ip6', 'inet']:
            logging.error(f"Configuration error, family of {fqdn} not: ip, ip6 or inet")
            sys.exit(1)

        table = self.config[section].get('table', 'filter')
        set_name = self.config[section]['set_name']
        
        # 确定IP类型
        if self.is_dry_run():
            typeof = 4
        else:
            typeof = self.get_set_type(family, table, set_name)

        return entry.ModelEntry(
            set_name=set_name, family=family, table=table, typeof=typeof,
            fqdn=fqdn, ip_list=None, ttl=None, next_update=None
        )

    def get_set_type(self, family, table, set_name):
        """获取nftables set的类型"""
        res = self.run_command(f"nft list set {family} {table} {set_name}")
        if "type ipv4_addr" in res:
            logging.debug(f"set {set_name} well defined in ipv4_addr family")
            return 4
        elif "type ipv6_addr" in res:
            logging.debug(f"set {set_name} well defined in ipv6_addr family")
            return 6
        else:
            logging.error(f"Type of {set_name} set not defined as ipv4_addr or ipv6_addr")
            sys.exit(1)

    def is_dry_run(self):
        """检查是否处于dry-run模式"""
        return (self.args.dry_run or 
                self.config.getboolean('GLOBAL', 'dry_run', fallback=False))

    def read_config(self):
        """读取并解析配置"""
        self.read_config_files()
        logging.info("# Parsing the configuration")

        self.entries = []
        for section in self.config.sections():
            if section != 'GLOBAL' and self.config.getboolean(section, 'enable', fallback=False):
                domains = [d.strip() for d in self.config[section]["domains"].split(',') if d.strip()]
                for fqdn in domains:
                    entry = self.create_entry(section, fqdn)
                    self.entries.append(entry)
                    logging.debug(entry)

        if not self.entries:
            logging.error("No entries configured, Exiting...")
            sys.exit(1)

        logging.info("# End of Parsing")

    def run_command(self, cmd):
        """执行系统命令"""
        logging.debug(f"Command to run: {cmd}")
        
        if self.is_dry_run():
            logging.debug("Dry-run detected, command not executed")
            return "dry-run-output"

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, shell=True, timeout=30)
            return result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logging.error(f"Command failed: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                logging.error(f"stderr: {e.stderr}")
            raise
        except FileNotFoundError:
            logging.error("nft command not found. Use --dry-run to avoid nftable changes")
            sys.exit(1)

    def get_current_set_ips(self, entry):
        """获取set中当前存在的IP列表"""
        try:
            res = self.run_command(f"nft list set {entry.family} {entry.table} {entry.set_name}")
            ips = []
            for line in res.split('\n'):
                line = line.strip()
                if line and not line.startswith(('elements = {', '}')):
                    ip = line.rstrip(',').split('#')[0].strip()
                    if ip and ('.' in ip or ':' in ip):
                        ips.append(ip)
            return ips
        except Exception as e:
            logging.error(f"Failed to get current IPs for set {entry.set_name}: {e}")
            return []

    def sync_set_ips(self, entry, current_ips):
        """同步set中的IP地址"""
        if not entry.ip_list:
            return True

        missing_ips = [ip for ip in entry.ip_list if str(ip) not in current_ips]
        if not missing_ips:
            return True

        ip_str = ', '.join(str(ip) for ip in missing_ips)
        add_cmd = f"nft add element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"
        
        try:
            self.run_command(add_cmd)
            logging.info(f"Restored {len(missing_ips)} missing IPs for set {entry.set_name}")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to restore IPs for set {entry.set_name}: {e}")
            return False

    def safe_delete_element(self, entry, ip_list):
        """安全删除元素"""
        if not ip_list:
            return True

        ip_str = ', '.join(str(ip) for ip in ip_list)
        delete_cmd = f"nft delete element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"

        try:
            self.run_command(delete_cmd)
            return True
        except subprocess.CalledProcessError:
            # 先添加再删除
            add_cmd = f"nft add element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"
            try:
                self.run_command(add_cmd)
                self.run_command(delete_cmd)
                logging.info(f"Recovered set {entry.set_name} operations")
                return True
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to recover set {entry.set_name}: {e}")
                return False

    def update_dns(self):
        """更新DNS解析结果"""
        resolver = self.get_resolver()
        
        # 修复这里：使用正确的fallback参数
        max_ttl = self.config.getint('GLOBAL', 'max_ttl', fallback=86400)
        min_ttl = self.config.getint('GLOBAL', 'min_ttl', fallback=300)
        
        current_time = datetime.now()

        for entry_item in self.entries:
            if entry_item.next_update and entry_item.next_update > current_time:
                continue

            old_ip_list = entry_item.ip_list
            logging.debug(f"Updating {entry_item.fqdn}...")

            try:
                new_ip_list, ttl = self.resolve_dns(entry_item, resolver)
                entry_item.ip_list = new_ip_list
                entry_item.ttl = ttl
                entry_item.next_update = current_time + timedelta(
                    seconds=max(min(ttl, max_ttl) + 1, min_ttl)
                )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
                logging.warning(f"Failed to resolve {entry_item.fqdn}: {e}")
                if not entry_item.next_update:
                    entry_item.next_update = current_time + timedelta(seconds=min_ttl)
                continue

            if old_ip_list != new_ip_list:
                logging.info(f"Updating {entry_item.fqdn} with {new_ip_list}")
                self.apply_config_entry(entry_item, old_ip_list)
            else:
                logging.debug(f"No changes for {entry_item.fqdn}")

            # 确保set中的IP与解析结果一致
            current_ips = self.get_current_set_ips(entry_item)
            self.sync_set_ips(entry_item, current_ips)

    def get_resolver(self):
        """获取DNS解析器"""
        if self.config.has_option('GLOBAL', 'custom_resolver'):
            return dns.resolver.make_resolver_at(self.config['GLOBAL']['custom_resolver'])
        return dns.resolver.Resolver()

    def resolve_dns(self, entry_item, resolver):
        """解析DNS记录"""
        rd_type = "A" if entry_item.typeof == 4 else "AAAA"
        answer = resolver.resolve(entry_item.fqdn, rdtype=rd_type, lifetime=10)
        return sorted(item.address for item in answer.rrset), answer.rrset.ttl

    def apply_config_entry(self, entry_item, old_ip_list):
        """应用配置变更"""
        current_ips = self.get_current_set_ips(entry_item)
        
        # 添加新IP
        if entry_item.ip_list:
            ip_str = ', '.join(str(ip) for ip in entry_item.ip_list)
            self.run_command(f"nft add element {entry_item.family} {entry_item.table} {entry_item.set_name} {{{ip_str}}}")

        # 删除旧IP
        if old_ip_list:
            ips_to_delete = [ip for ip in old_ip_list if ip not in entry_item.ip_list]
            if ips_to_delete:
                self.safe_delete_element(entry_item, ips_to_delete)

    def get_next_run_time(self):
        """计算下次运行时间"""
        if not self.entries:
            return datetime.now() + timedelta(seconds=300)

        next_updates = (e.next_update for e in self.entries if e.next_update)
        valid_updates = [nu for nu in next_updates if nu]
        return min(valid_updates) if valid_updates else datetime.now() + timedelta(seconds=300)

    def cleanup(self):
        """清理所有配置"""
        if self.is_dry_run():
            return

        logging.info("Cleaning all entries")
        for entry_item in self.entries:
            if entry_item.ip_list:
                self.safe_delete_element(entry_item, entry_item.ip_list)

    def run_loop(self):
        """主循环"""
        last_memory_check = datetime.now()
        MEMORY_CHECK_INTERVAL = 20

        while not self.stop:
            self.update_dns()

            # 内存检查
            current_time = datetime.now()
            if (current_time - last_memory_check).seconds >= MEMORY_CHECK_INTERVAL:
                self.check_memory_usage()
                last_memory_check = current_time

            # 等待下次运行
            next_run = self.get_next_run_time()
            sleep_seconds = max(1, (next_run - current_time).total_seconds())
            logging.info(f"Sleeping for {sleep_seconds:.0f}s")

            # 分段sleep以便及时响应停止信号
            sleep_interval = min(5, sleep_seconds)
            remaining_sleep = sleep_seconds
            while remaining_sleep > 0 and not self.stop:
                sleep(min(sleep_interval, remaining_sleep))
                remaining_sleep -= sleep_interval

        self.cleanup()

    def check_memory_usage(self):
        """检查内存使用情况"""
        MEMORY_LIMIT_MB = 100
        current_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        if current_memory > MEMORY_LIMIT_MB:
            logging.warning(f"Memory usage high: {current_memory:.2f}MB, triggering GC")
            gc.collect()
            logging.info(f"After GC: {resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.2f}MB")

    def main(self):
        """主函数"""
        try:
            self.read_config()
            self.check_memory_usage()
            self.run_loop()
        except KeyboardInterrupt:
            logging.info("Program interrupted by user")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            sys.exit(1)

if __name__ == '__main__':
    DNSNFTManager().main()

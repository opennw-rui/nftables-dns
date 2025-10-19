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
import hashlib
import re

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

        # 缓存机制
        self.set_cache = {}  # 缓存set的当前状态 {(family, table, set_name): set_of_ips}
        self.cache_last_updated = {}  # 记录缓存最后更新时间
        self.CACHE_TTL = 300  # 缓存有效期5分钟

        # 配置文件监控
        self.config_hash = None  # 记录配置文件的哈希值
        self.last_entries_map = {}  # 记录上次的条目映射 {(family, table, set_name, fqdn): entry}

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

    def get_config_files_list(self):
        """获取所有配置文件的列表"""
        config_files = [Path(self.args.config_file)]

        if self.config.has_option('GLOBAL', 'include_config_dir'):
            config_dir = Path(self.config['GLOBAL']['include_config_dir'])
            if config_dir.is_dir():
                config_files.extend(config_dir.glob("*.conf"))

        return config_files

    def calculate_config_hash(self):
        """计算配置文件的哈希值，用于检测配置变化"""
        config_files = self.get_config_files_list()
        content_hash = hashlib.md5()

        for config_file in config_files:
            if config_file.is_file():
                # 添加文件路径和修改时间到哈希计算
                mtime = config_file.stat().st_mtime
                content_hash.update(f"{config_file}:{mtime}".encode())

        return content_hash.hexdigest()

    def has_config_changed(self):
        """检查配置文件是否发生变化"""
        current_hash = self.calculate_config_hash()
        return current_hash != self.config_hash

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

        # 更新配置文件哈希
        self.config_hash = self.calculate_config_hash()

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

        logging.info(f"# End of Parsing, found {len(self.entries)} entries")

    def check_and_reload_config(self):
        """检查配置文件变化并重新加载，处理域名增减"""
        if self.has_config_changed():
            logging.info("Configuration changed, reloading...")

            # 保存旧的条目信息用于比较
            old_entries_map = self.last_entries_map.copy()

            # 重新读取配置
            old_entries = self.entries.copy()
            self.read_config()

            # 更新当前条目映射
            current_entries_map = {(e.family, e.table, e.set_name, e.fqdn): e for e in self.entries}

            # 找出新增的域名和删除的域名
            added_entries = set(current_entries_map.keys()) - set(old_entries_map.keys())
            removed_entries = set(old_entries_map.keys()) - set(current_entries_map.keys())

            # 立即处理新增的域名
            for entry_key in added_entries:
                entry_item = current_entries_map[entry_key]
                logging.info(f"New domain detected: {entry_item.fqdn}, processing immediately")
                # 强制立即解析和同步新域名
                entry_item.next_update = datetime.now()

            # 处理删除的域名 - 清理对应的IP
            for entry_key in removed_entries:
                old_entry = old_entries_map[entry_key]
                logging.info(f"Domain removed: {old_entry.fqdn}, cleaning up IPs from set")
                self.cleanup_removed_domain(old_entry)

            # 更新最后条目映射
            self.last_entries_map = current_entries_map

            return True
        return False

    def cleanup_removed_domain(self, removed_entry):
        """清理被删除域名对应的IP"""
        if not removed_entry.ip_list:
            logging.debug(f"No IPs to clean for removed domain {removed_entry.fqdn}")
            return

        # 获取当前set中的IP
        current_ips = self.get_current_set_ips(removed_entry, force_refresh=True)
        removed_ips = set(str(ip) for ip in removed_entry.ip_list)

        # 找出需要删除的IP（只删除该域名对应的IP）
        ips_to_remove = removed_ips & current_ips

        if ips_to_remove:
            logging.info(f"Removing {len(ips_to_remove)} IPs for deleted domain {removed_entry.fqdn}")
            self.safe_delete_element(removed_entry, list(ips_to_remove))
        else:
            logging.debug(f"No IPs found to remove for deleted domain {removed_entry.fqdn}")

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
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                logging.error(f"stderr: {e.stderr}")
            raise
        except subprocess.TimeoutExpired as e:
            logging.error(f"Command timeout: {e}")
            raise
        except FileNotFoundError:
            logging.error("nft command not found. Use --dry-run to avoid nftable changes")
            sys.exit(1)

    def _parse_nft_elements(self, nft_output):
        """
        解析 nft list set 的输出，返回 set of ip strings。
        能处理单行: elements = { 1.2.3.4, 2.3.4.5 }
        也能处理多行:
            elements = {
                1.2.3.4,
                2.3.4.5
            }
        如果没有 elements 块，则返回空集。
        """
        if not nft_output:
            return set()

        # 找到第一个 `{` 和最后一个 `}` 之间的内容（谨慎）
        m = re.search(r'elements\s*=\s*\{(.*)\}', nft_output, flags=re.S)
        if not m:
            # 可能是 multi-line，没有在同一行匹配到 }, 尝试提取从 'elements = {' 开始直到单独一行 '}' 的内容
            m2 = re.search(r'elements\s*=\s*\{(.*)', nft_output, flags=re.S)
            if not m2:
                return set()
            # 截取从 m2.start 到末尾，再手工找到第一个独立的 '}' 行
            tail = nft_output[m2.start():]
            # 再找匹配的闭合 '}'（第一个匹配）
            m3 = re.search(r'\{(.*?)}', tail, flags=re.S)
            if not m3:
                content = tail
            else:
                content = m3.group(1)
        else:
            content = m.group(1)

        # content 可能包含换行与注释，按逗号拆分并清理
        parts = []
        for piece in re.split(r',', content):
            piece = piece.strip()
            # 移除内联注释 (# 后面的)
            piece = re.sub(r'#.*$', '', piece).strip()
            if not piece:
                continue
            # 只保留看起来像 IP 的内容
            if re.search(r'[0-9a-fA-F:\.]+', piece):
                # 清理掉可能残留的花括号或逗号
                piece = piece.strip(' ,{}')
                if piece:
                    parts.append(piece)
        return set(parts)

    def get_current_set_ips(self, entry, force_refresh=False):
        """获取set中当前存在的IP列表（智能缓存）"""
        cache_key = (entry.family, entry.table, entry.set_name)
        current_time = datetime.now()

        # 检查是否需要刷新缓存
        should_refresh = (
            force_refresh or
            cache_key not in self.set_cache or
            cache_key not in self.cache_last_updated or
            (current_time - self.cache_last_updated[cache_key]).seconds > self.CACHE_TTL
        )

        if not should_refresh:
            return self.set_cache[cache_key]

        # 从nftables获取实时数据并更新缓存
        try:
            res = self.run_command(f"nft list set {entry.family} {entry.table} {entry.set_name}")
            ips = self._parse_nft_elements(res)
            self.set_cache[cache_key] = ips
            self.cache_last_updated[cache_key] = current_time
            logging.debug(f"Refreshed cache for set {entry.set_name}: {len(ips)} IPs")
            return ips
        except Exception as e:
            logging.error(f"Failed to get current IPs for set {entry.set_name}: {e}")
            # 如果获取失败但缓存中有数据，返回缓存数据
            if cache_key in self.set_cache:
                logging.warning(f"Using cached data for set {entry.set_name} due to error")
                return self.set_cache[cache_key]
            return set()

    def update_set_cache(self, entry, new_ips):
        """更新set缓存"""
        cache_key = (entry.family, entry.table, entry.set_name)
        self.set_cache[cache_key] = set(new_ips)
        self.cache_last_updated[cache_key] = datetime.now()
        logging.debug(f"Updated cache for set {entry.set_name}")

    def sync_set_ips(self, entry):
        """同步set中的IP地址 - 智能版本"""
        if not entry.ip_list:
            return True

        # 强制刷新缓存，确保检测到手动删除
        current_ips = self.get_current_set_ips(entry, force_refresh=True)
        target_ip_set = set(str(ip) for ip in entry.ip_list)

        missing_ips = target_ip_set - current_ips

        if not missing_ips:
            logging.debug(f"Set {entry.set_name} is already in sync")
            return True

        # 添加缺失的IP
        ip_str = ', '.join(str(ip) for ip in missing_ips)
        add_cmd = f"nft add element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"

        try:
            self.run_command(add_cmd)
            # 更新缓存为正确状态
            self.update_set_cache(entry, current_ips | missing_ips)
            logging.info(f"Restored {len(missing_ips)} missing IPs for set {entry.set_name}")
            return True
        except Exception as e:
            logging.error(f"Failed to restore IPs for set {entry.set_name}: {e}")
            # 命令失败时清除缓存，强制下次刷新
            cache_key = (entry.family, entry.table, entry.set_name)
            if cache_key in self.set_cache:
                del self.set_cache[cache_key]
            if cache_key in self.cache_last_updated:
                del self.cache_last_updated[cache_key]
            return False

    def safe_delete_element(self, entry, ip_list):
        """安全删除元素"""
        if not ip_list:
            return True

        # 统一清理 ip_list 中的字符串，防止残留大括号等
        clean_ips = [re.sub(r'[{}\s,]+', '', str(ip)).strip() for ip in ip_list if ip]
        clean_ips = [ip for ip in clean_ips if ip]
        if not clean_ips:
            logging.debug("No valid IPs to delete after cleaning")
            return True

        ip_str = ', '.join(str(ip) for ip in clean_ips)
        delete_cmd = f"nft delete element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"

        try:
            self.run_command(delete_cmd)
            # 更新缓存
            cache_key = (entry.family, entry.table, entry.set_name)
            if cache_key in self.set_cache:
                ip_set = set(clean_ips)
                self.set_cache[cache_key] = self.set_cache[cache_key] - ip_set
                self.cache_last_updated[cache_key] = datetime.now()
            return True
        except subprocess.CalledProcessError:
            # 先添加再删除（恢复可能缺失的元素再删）
            add_cmd = f"nft add element {entry.family} {entry.table} {entry.set_name} {{{ip_str}}}"
            try:
                self.run_command(add_cmd)
                self.run_command(delete_cmd)
                # 更新缓存
                cache_key = (entry.family, entry.table, entry.set_name)
                if cache_key in self.set_cache:
                    ip_set = set(clean_ips)
                    self.set_cache[cache_key] = self.set_cache[cache_key] - ip_set
                    self.cache_last_updated[cache_key] = datetime.now()
                logging.info(f"Recovered set {entry.set_name} operations")
                return True
            except Exception as e:
                logging.error(f"Failed to recover set {entry.set_name}: {e}")
                # 命令失败时清除缓存
                cache_key = (entry.family, entry.table, entry.set_name)
                if cache_key in self.set_cache:
                    del self.set_cache[cache_key]
                if cache_key in self.cache_last_updated:
                    del self.cache_last_updated[cache_key]
                return False
        except Exception as e:
            logging.error(f"Unexpected error while deleting elements: {e}")
            return False

    def update_dns(self):
        """更新DNS解析结果"""
        resolver = self.get_resolver()

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
            except Exception as e:
                logging.error(f"Unexpected DNS error for {entry_item.fqdn}: {e}")
                entry_item.next_update = current_time + timedelta(seconds=min_ttl)
                continue

            if old_ip_list != new_ip_list:
                logging.info(f"Updating {entry_item.fqdn} with {new_ip_list}")
                self.apply_config_entry(entry_item, old_ip_list)
            else:
                logging.debug(f"No changes for {entry_item.fqdn}")

            # 确保set中的IP与解析结果一致
            # 这里使用智能同步，会强制刷新缓存来检测手动删除
            self.sync_set_ips(entry_item)

    def get_resolver(self):
        """获取DNS解析器，支持 custom_resolver"""
        if self.config.has_option('GLOBAL', 'custom_resolver'):
            try:
                r = dns.resolver.Resolver(configure=False)
                # 只支持单个地址配置，若配置多个请用逗号分隔并取第一个
                nameserver = self.config['GLOBAL']['custom_resolver'].strip()
                if ',' in nameserver:
                    nameserver = nameserver.split(',')[0].strip()
                r.nameservers = [nameserver]
                logging.debug(f"Using custom resolver {nameserver}")
                return r
            except Exception as e:
                logging.warning(f"Failed to configure custom resolver {e}, falling back to system resolver")
        return dns.resolver.Resolver()

    def resolve_dns(self, entry_item, resolver):
        """解析DNS记录"""
        rd_type = "A" if entry_item.typeof == 4 else "AAAA"
        answer = resolver.resolve(entry_item.fqdn, rdtype=rd_type, lifetime=10)
        # 将返回的结果转换为字符串列表并排序，ttl 取 rrset.ttl
        ip_list = sorted(str(item.address) for item in answer)
        ttl = getattr(answer.rrset, 'ttl', 300)
        return ip_list, ttl

    def apply_config_entry(self, entry_item, old_ip_list):
        """应用配置变更"""
        # 获取当前IP（使用缓存，不强制刷新）
        current_ips = self.get_current_set_ips(entry_item, force_refresh=False)

        # 转换为集合进行比较
        old_ip_set = set(str(ip) for ip in (old_ip_list or []))
        new_ip_set = set(str(ip) for ip in (entry_item.ip_list or []))
        current_ip_set = set(current_ips)

        # 需要添加的IP：在新的IP列表中但不在当前set中的
        ips_to_add = new_ip_set - current_ip_set

        # 需要删除的IP：在旧的IP列表中但不在新的IP列表中，并且当前在set中的
        ips_to_delete = (old_ip_set - new_ip_set) & current_ip_set

        # 添加新IP
        if ips_to_add:
            ip_str = ', '.join(str(ip) for ip in ips_to_add)
            add_cmd = f"nft add element {entry_item.family} {entry_item.table} {entry_item.set_name} {{{ip_str}}}"
            try:
                self.run_command(add_cmd)
                logging.info(f"Added {len(ips_to_add)} IPs for {entry_item.fqdn}")
                # 更新缓存
                self.update_set_cache(entry_item, current_ip_set | ips_to_add)
            except Exception as e:
                logging.error(f"Failed to add IPs for {entry_item.fqdn}: {e}")
                # 删除缓存，强制下次刷新
                cache_key = (entry_item.family, entry_item.table, entry_item.set_name)
                if cache_key in self.set_cache:
                    del self.set_cache[cache_key]
                if cache_key in self.cache_last_updated:
                    del self.cache_last_updated[cache_key]

        # 删除旧IP
        if ips_to_delete:
            self.safe_delete_element(entry_item, list(ips_to_delete))

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
        MEMORY_CHECK_INTERVAL = 300
        last_config_check = datetime.now()
        CONFIG_CHECK_INTERVAL = 30  # 每30秒检查一次配置变化

        # 初始化条目映射
        self.last_entries_map = {(e.family, e.table, e.set_name, e.fqdn): e for e in self.entries}

        while not self.stop:
            current_time = datetime.now()

            # 定期检查配置变化
            if (current_time - last_config_check).seconds >= CONFIG_CHECK_INTERVAL:
                config_changed = self.check_and_reload_config()
                if config_changed:
                    logging.info("Configuration reloaded successfully")
                last_config_check = current_time

            self.update_dns()

            # 内存检查
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
        MEMORY_LIMIT_MB = 80
        current_memory = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        if current_memory > MEMORY_LIMIT_MB:
            logging.warning(f"Memory usage high: {current_memory:.2f}MB, triggering GC")
            gc.collect()
            # 同时清理缓存
            self.set_cache.clear()
            self.cache_last_updated.clear()
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

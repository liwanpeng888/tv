#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
直播源响应时间检测工具
功能：检测远程直播源的响应时间
特点：
- 已在blacklist_auto中的链接直接判定失败，不检测
- 白名单失败显示0.00ms，不加入黑名单
- 新的失败链接追加到blacklist_auto
"""

import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import ssl
import re
from typing import List, Tuple, Set
import logging

# 获取文件路径
def get_file_paths():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    return {
        "urls": os.path.join(parent_dir, 'urls.txt'),
        "blacklist_auto": os.path.join(current_dir, 'blacklist_auto.txt'),
        "whitelist_manual": os.path.join(current_dir, 'whitelist_manual.txt'),
        "whitelist_auto": os.path.join(current_dir, 'whitelist_auto.txt'),
        "whitelist_respotime": os.path.join(current_dir, 'whitelist_respotime.txt'),
        "log": os.path.join(current_dir, 'log.txt')
    }

FILE_PATHS = get_file_paths()

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(FILE_PATHS["log"], mode='a', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    USER_AGENT_URL = "okhttp/3.14.9"
    
    TIMEOUT_FETCH = 5       # 拉取远程源超时
    TIMEOUT_CHECK = 2.5     # 链接检测超时
    TIMEOUT_CONNECT = 1.5   # 连接超时
    TIMEOUT_READ = 1.5      # 读取超时
    
    MAX_WORKERS = 30        # 并发线程数

class StreamChecker:
    def __init__(self):
        self.start_time = datetime.now()
        self.ipv6_available = self._check_ipv6()
        self.blacklist_urls = self._load_blacklist()  # 黑名单URL集合
        self.whitelist_urls = set()                    # 白名单URL集合
        self.whitelist_lines = []                       # 白名单完整行
        self.new_failed_urls = set()                    # 新发现的失败链接

    def _check_ipv6(self):
        """检查IPv6支持"""
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('2001:4860:4860::8888', 53))
            sock.close()
            return result == 0
        except:
            return False

    def _load_blacklist(self) -> Set[str]:
        """加载黑名单文件中的所有URL"""
        blacklist = set()
        try:
            if os.path.exists(FILE_PATHS["blacklist_auto"]):
                with open(FILE_PATHS["blacklist_auto"], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # 跳过注释行和空行
                        if not line or line.startswith('更新时间') or line.startswith('blacklist'):
                            continue
                        # 提取URL（可能是"失败次数,时间,URL"格式或直接URL）
                        if ',' in line:
                            parts = line.split(',')
                            url = parts[-1].strip()  # 取最后一部分作为URL
                        else:
                            url = line
                        
                        if '://' in url:
                            blacklist.add(url)
                logger.info(f"加载黑名单: {len(blacklist)} 个链接")
        except Exception as e:
            logger.error(f"加载黑名单失败: {e}")
        return blacklist

    def _save_blacklist(self):
        """保存新发现的失败链接到黑名单文件"""
        if not self.new_failed_urls:
            return
        
        try:
            # 读取现有内容
            existing_lines = []
            if os.path.exists(FILE_PATHS["blacklist_auto"]):
                with open(FILE_PATHS["blacklist_auto"], 'r', encoding='utf-8') as f:
                    existing_lines = [line.rstrip('\n') for line in f]
            
            # 生成新的黑名单条目
            new_lines = []
            for url in self.new_failed_urls:
                # 格式: 失败次数,时间戳,URL (简单版本只存URL)
                new_lines.append(url)
            
            # 合并去重
            all_urls = set()
            all_content = []
            
            # 保留头部
            for line in existing_lines:
                if line.startswith('更新时间') or line.startswith('blacklist'):
                    all_content.append(line)
                else:
                    # 提取URL
                    if ',' in line:
                        url = line.split(',')[-1].strip()
                    else:
                        url = line
                    if url not in all_urls:
                        all_urls.add(url)
                        all_content.append(line)
            
            # 添加新链接
            for url in new_lines:
                if url not in all_urls:
                    all_urls.add(url)
                    all_content.append(url)
            
            # 写入文件
            os.makedirs(os.path.dirname(FILE_PATHS["blacklist_auto"]), exist_ok=True)
            with open(FILE_PATHS["blacklist_auto"], 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_content))
            
            logger.info(f"黑名单已更新: 新增 {len(self.new_failed_urls)} 个失败链接")
            logger.info(f"黑名单总数: {len(all_urls)} 个")
            
        except Exception as e:
            logger.error(f"保存黑名单失败: {e}")

    def read_file(self, file_path):
        """读取文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return []

    def create_ssl_context(self):
        """创建SSL上下文"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def check_http(self, url, timeout):
        """检测HTTP/HTTPS"""
        start = time.perf_counter()
        try:
            headers = {
                "User-Agent": Config.USER_AGENT,
                "Connection": "close",
                "Range": "bytes=0-512"
            }
            req = urllib.request.Request(url, headers=headers, method="HEAD")
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self.create_ssl_context())
            )
            with opener.open(req, timeout=timeout) as resp:
                elapsed = (time.perf_counter() - start) * 1000
                return 200 <= resp.getcode() < 400, round(elapsed, 2)
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - start) * 1000
            return e.code in [301, 302], round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start) * 1000
            return False, round(elapsed, 2)

    def check_rtmp_rtsp(self, url, timeout):
        """检测RTMP/RTSP"""
        start = time.perf_counter()
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False, round((time.perf_counter() - start) * 1000, 2)
            
            port = parsed.port or (1935 if url.startswith('rtmp') else 554)
            
            # DNS解析
            ips = []
            try:
                addrs = socket.getaddrinfo(parsed.hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                ips = [(addr[4][0], addr[0]) for addr in addrs[:2]]
            except:
                pass
            
            for ip, af in ips:
                sock = None
                try:
                    sock = socket.socket(af, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    sock.connect((ip, port))
                    
                    if url.startswith('rtmp'):
                        sock.send(b'\x03')
                        sock.settimeout(Config.TIMEOUT_READ)
                        data = sock.recv(1)
                        elapsed = (time.perf_counter() - start) * 1000
                        return bool(data), round(elapsed, 2)
                    else:  # rtsp
                        elapsed = (time.perf_counter() - start) * 1000
                        return True, round(elapsed, 2)
                except:
                    continue
                finally:
                    if sock:
                        sock.close()
            
            return False, round((time.perf_counter() - start) * 1000, 2)
        except:
            elapsed = (time.perf_counter() - start) * 1000
            return False, round(elapsed, 2)

    def check_url(self, url, is_whitelist=False):
        """检测单个URL"""
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')
            timeout = Config.TIMEOUT_CHECK * 1.5 if is_whitelist else Config.TIMEOUT_CHECK
            
            if url.startswith(('http://', 'https://')):
                return self.check_http(encoded_url, timeout)
            elif url.startswith(('rtmp://', 'rtsp://')):
                return self.check_rtmp_rtsp(encoded_url, timeout)
            else:
                # 其他协议只检测端口
                start = time.perf_counter()
                parsed = urlparse(url)
                if not parsed.hostname:
                    return False, round((time.perf_counter() - start) * 1000, 2)
                
                port = parsed.port or 80
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.TIMEOUT_CONNECT)
                sock.connect((parsed.hostname, port))
                sock.close()
                elapsed = (time.perf_counter() - start) * 1000
                return True, round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start) * 1000
            return False, round(elapsed, 2)

    def fetch_remote(self, urls):
        """拉取远程源"""
        all_lines = []
        for url in urls:
            try:
                req = urllib.request.Request(
                    quote(unquote(url), safe=':/?&=#'),
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    
                    if "#EXTM3U" in content:
                        lines = self.parse_m3u(content)
                    else:
                        lines = [line.strip() for line in content.split('\n') 
                                if line.strip() and '://' in line and ',' in line]
                    
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取 {len(lines)} 个链接")
            except Exception as e:
                logger.error(f"拉取失败 {url}: {e}")
        return all_lines

    def parse_m3u(self, content):
        """解析M3U"""
        lines = []
        current_name = ""
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith("#EXTINF"):
                match = re.search(r',(.+)$', line)
                if match:
                    current_name = match.group(1).strip()
            elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')) and current_name:
                lines.append(f"{current_name},{line}")
                current_name = ""
        return lines

    def load_whitelist(self):
        """加载白名单"""
        whitelist_raw = self.read_file(FILE_PATHS["whitelist_manual"])
        for line in whitelist_raw:
            if ',' in line and '://' in line:
                name, url = line.split(',', 1)
                url = url.strip()
                self.whitelist_urls.add(url)
                self.whitelist_lines.append(line)
        logger.info(f"白名单: {len(self.whitelist_urls)} 个")

    def prepare_lines(self, lines):
        """
        准备待检测行：
        1. 已在黑名单中的直接标记为失败（不检测）
        2. 返回需要检测的链接和预失败的链接
        """
        to_check = []        # 需要检测的链接
        pre_failed = []      # 黑名单中已有的链接（直接失败）
        url_to_line = {}      # URL到完整行的映射
        
        blacklist_skip = 0
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            
            name, url = line.split(',', 1)
            url = url.strip().split('#')[0].split('$')[0]
            
            # 保存映射
            url_to_line[url] = f"{name},{url}"
            
            # 检查是否在黑名单中
            if url in self.blacklist_urls:
                # 黑名单中的链接直接判定失败
                if url not in self.whitelist_urls:  # 白名单除外
                    pre_failed.append((url, line))
                    blacklist_skip += 1
                    continue
            
            # 需要检测的链接
            to_check.append((url, line))
        
        logger.info(f"黑名单直接跳过: {blacklist_skip} 个")
        logger.info(f"需要检测: {len(to_check)} 个")
        
        return to_check, pre_failed, url_to_line

    def batch_check(self, to_check, url_to_line):
        """批量检测（只检测需要检测的链接）"""
        success = []  # 所有白名单 + 有效链接
        failed = []   # 非白名单失败（新发现的）
        
        total = len(to_check)
        logger.info(f"开始检测 {total} 个链接")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {}
            for url, line in to_check:
                is_whitelist = url in self.whitelist_urls
                futures[executor.submit(self.check_url, url, is_whitelist)] = (url, line, is_whitelist)
            
            processed = 0
            for future in as_completed(futures):
                url, line, is_whitelist = futures[future]
                processed += 1
                
                try:
                    is_valid, resp_time = future.result()
                    
                    if is_valid:
                        success.append((url_to_line[url], resp_time))
                    else:
                        if is_whitelist:
                            # 白名单失败：显示0.00ms，不加入黑名单
                            success.append((url_to_line[url], 0.00))
                        else:
                            # 非白名单失败：加入黑名单
                            failed.append(url_to_line[url])
                            self.new_failed_urls.add(url)
                except:
                    if is_whitelist:
                        success.append((url_to_line[url], 0.00))
                    else:
                        failed.append(url_to_line[url])
                        self.new_failed_urls.add(url)
                
                if processed % 50 == 0:
                    valid = sum(1 for _, t in success if t > 0)
                    logger.info(f"进度: {processed}/{total} | 有效: {valid} | 白名单失败: {len(success)-valid} | 新失败: {len(failed)}")
        
        # 按响应时间排序
        success.sort(key=lambda x: x[1])
        valid = sum(1 for _, t in success if t > 0)
        logger.info(f"检测完成 - 有效: {valid} | 白名单失败: {len(success)-valid} | 新失败: {len(failed)}")
        
        return success, failed

    def save_results(self, success, failed, pre_failed):
        """保存结果"""
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"

        # 带响应时间（所有白名单 + 有效链接）
        resp_lines = [
            "更新时间,#genre#", version, "", "响应时间,名称,URL,#genre#"
        ] + [f"{t:.2f}ms,{line}" for line, t in success]
        
        # 纯净列表（所有白名单 + 有效链接）
        clean_lines = [
            "更新时间,#genre#", version, "", "直播源,#genre#"
        ] + [line for line, _ in success]
        
        # 失败列表（新发现的失败 + 黑名单预失败的）
        all_failed = failed + [line for _, line in pre_failed]
        fail_lines = [
            "更新时间,#genre#", version, "", "失败链接,#genre#"
        ] + all_failed

        # 写入文件
        self._write_file(FILE_PATHS["whitelist_respotime"], resp_lines)
        self._write_file(FILE_PATHS["whitelist_auto"], clean_lines)
        self._write_file(FILE_PATHS["blacklist_auto"], fail_lines)
        
        logger.info(f"结果已保存")
        logger.info(f"  - whitelist_respotime.txt: {len(success)} 条")
        logger.info(f"  - whitelist_auto.txt: {len(success)} 条")
        logger.info(f"  - blacklist_auto.txt: {len(all_failed)} 条")

    def _write_file(self, path, lines):
        """写入文件"""
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
        except Exception as e:
            logger.error(f"写入失败 {path}: {e}")

    def run(self):
        """主函数"""
        logger.info("=" * 50)
        logger.info("直播源检测工具")
        logger.info("=" * 50)
        
        # 1. 加载白名单
        self.load_whitelist()
        
        # 2. 读取远程源列表
        remote_urls = self.read_file(FILE_PATHS["urls"])
        if not remote_urls:
            logger.error("未找到 urls.txt")
            return
        
        # 3. 拉取远程源
        all_lines = self.fetch_remote(remote_urls)
        
        # 4. 合并白名单
        all_lines.extend(self.whitelist_lines)
        
        # 5. 准备数据：区分黑名单和需要检测的
        to_check, pre_failed, url_to_line = self.prepare_lines(all_lines)
        
        # 6. 批量检测
        success, failed = self.batch_check(to_check, url_to_line)
        
        # 7. 保存黑名单（新发现的失败链接）
        self._save_blacklist()
        
        # 8. 保存结果
        self.save_results(success, failed, pre_failed)
        
        # 9. 统计
        elapsed = datetime.now() - self.start_time
        valid = sum(1 for _, t in success if t > 0)
        logger.info("=" * 50)
        logger.info(f"总耗时: {elapsed.total_seconds():.1f} 秒")
        logger.info(f"有效链接: {valid} 个")
        logger.info(f"白名单失败: {len(success)-valid} 个 (0.00ms)")
        logger.info(f"新失败链接: {len(failed)} 个")
        logger.info(f"黑名单跳过: {len(pre_failed)} 个")
        logger.info("=" * 50)

if __name__ == "__main__":
    checker = StreamChecker()
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("用户中断")
    except Exception as e:
        logger.error(f"出错: {e}")

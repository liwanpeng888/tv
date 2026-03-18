#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
直播源响应时间检测工具
功能：检测远程直播源的响应时间
特点：白名单失败显示0.00ms，不加入失败列表
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

def get_file_paths():
    """获取文件路径（保持原有目录结构）"""
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

# 设置日志
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
    """配置类"""
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PotPlayer/1.7.21098"
    USER_AGENT_URL = "okhttp/3.14.9"

    TIMEOUT_FETCH = 5      # 拉取远程源超时
    TIMEOUT_CHECK = 3     # 检测超时
    TIMEOUT_CONNECT = 1.5   # 连接超时
    TIMEOUT_READ = 1.5      # 读取超时

    MAX_WORKERS = 20        # 并发数
    MAX_RETRIES = 0         # 重试次数


class StreamChecker:
    """直播源检测器"""
    
    def __init__(self):
        self.start_time = datetime.now()
        self.ipv6_available = self._check_ipv6_support()
        self.failed_urls = self._load_blacklist()  # 历史失败链接
        self.whitelist_urls = set()                 # 白名单链接集合
        self.whitelist_lines = []                    # 白名单完整行

    def _check_ipv6_support(self) -> bool:
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
        """加载历史失败链接"""
        failed_set = set()
        try:
            if os.path.exists(FILE_PATHS["blacklist_auto"]):
                with open(FILE_PATHS["blacklist_auto"], 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and ',' in line and '://' in line:
                            parts = line.split(',')
                            url = parts[-1].strip()
                            if url.startswith(('http', 'https', 'rtmp', 'rtsp')):
                                failed_set.add(url)
                logger.info(f"加载历史失败链接: {len(failed_set)} 个")
        except Exception as e:
            logger.error(f"加载黑名单失败: {e}")
        return failed_set

    def read_txt(self, file_path: str) -> List[str]:
        """读取文本文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []

    def create_ssl_context(self):
        """创建SSL上下文（忽略证书验证）"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        return context

    def fetch_remote_urls(self, urls: List[str]) -> List[str]:
        """拉取远程源"""
        all_lines = []
        for url in urls:
            try:
                # URL编码处理
                encoded_url = quote(unquote(url), safe=':/?&=#')
                
                req = urllib.request.Request(
                    encoded_url,
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    
                    # 判断是否为M3U格式
                    if "#EXTM3U" in content:
                        lines = self._parse_m3u(content)
                    else:
                        # 普通文本格式：名称,URL
                        lines = [
                            line.strip() for line in content.split('\n') 
                            if line.strip() and '://' in line and ',' in line
                        ]
                    
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取 {len(lines)} 个候选链接")
                    
            except Exception as e:
                logger.error(f"拉取远程源失败 {url}: {e}")
        
        return all_lines

    def _parse_m3u(self, content: str) -> List[str]:
        """解析M3U格式"""
        lines = []
        current_name = ""
        
        for line in content.split('\n'):
            line = line.strip()
            
            if line.startswith("#EXTINF"):
                match = re.search(r',(.+)$', line)
                if match:
                    current_name = match.group(1).strip()
                    
            elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')):
                if current_name:
                    lines.append(f"{current_name},{line}")
                    current_name = ""  # 重置
        
        return lines

    def load_whitelist(self):
        """加载白名单"""
        whitelist_raw = self.read_txt(FILE_PATHS["whitelist_manual"])
        
        for line in whitelist_raw:
            if ',' in line and '://' in line:
                name, url = line.split(',', 1)
                url = url.strip()
                self.whitelist_urls.add(url)
                self.whitelist_lines.append(line)
        
        logger.info(f"白名单有效链接: {len(self.whitelist_urls)} 个")

    def clean_deduplicate(self, lines: List[str]) -> List[str]:
        """清洗去重"""
        seen_urls = set()
        cleaned = []
        
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
                
            name, url = line.split(',', 1)
            url = url.strip().split('#')[0].split('$')[0]  # 去除参数
            
            # 过滤历史失败链接（白名单不过滤）
            if url in self.failed_urls and url not in self.whitelist_urls:
                continue
                
            # 去重
            if url not in seen_urls:
                seen_urls.add(url)
                cleaned.append(f"{name},{url}")
        
        logger.info(f"清洗后剩余 {len(cleaned)} 个待检测链接")
        return cleaned

    def check_http_url(self, url: str, timeout: float) -> Tuple[bool, float]:
        """检测HTTP/HTTPS源"""
        start_time = time.perf_counter()
        
        try:
            headers = {
                "User-Agent": Config.USER_AGENT,
                "Accept": "*/*",
                "Referer": "https://iptv-org.github.io/",
                "Connection": "close",
                "Range": "bytes=0-512"
            }
            
            req = urllib.request.Request(url, headers=headers, method="HEAD")
            
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=self.create_ssl_context()),
                urllib.request.HTTPRedirectHandler()
            )
            
            with opener.open(req, timeout=timeout) as resp:
                elapsed = (time.perf_counter() - start_time) * 1000
                return 200 <= resp.getcode() < 500, round(elapsed, 2)
                
        except urllib.error.HTTPError as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            # 某些重定向也算有效
            return e.code in [301, 302, 303, 307, 308], round(elapsed, 2)
            
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    def check_rtmp_rtsp_url(self, url: str, timeout: float) -> Tuple[bool, float]:
        """检测RTMP/RTSP源"""
        start_time = time.perf_counter()
        
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False, round((time.perf_counter() - start_time) * 1000, 2)
            
            port = parsed.port or (1935 if url.startswith('rtmp') else 554)
            
            # 地址解析
            addr_info = socket.getaddrinfo(
                parsed.hostname, port, 
                socket.AF_UNSPEC if self.ipv6_available else socket.AF_INET,
                socket.SOCK_STREAM
            )
            
            for res in addr_info:
                af, socktype, proto, _, sa = res
                sock = None
                
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(min(Config.TIMEOUT_CONNECT, timeout))
                    sock.connect(sa)
                    
                    if url.startswith('rtmp'):
                        sock.send(b'\x03')
                        sock.settimeout(Config.TIMEOUT_READ)
                        data = sock.recv(1)
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return bool(data), round(elapsed, 2)
                        
                    elif url.startswith('rtsp'):
                        req = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {Config.USER_AGENT}\r\n\r\n"
                        sock.send(req.encode())
                        sock.settimeout(Config.TIMEOUT_READ)
                        resp = sock.recv(1024)
                        elapsed = (time.perf_counter() - start_time) * 1000
                        return b'RTSP/1.0' in resp, round(elapsed, 2)
                        
                except:
                    continue
                    
                finally:
                    if sock:
                        sock.close()
            
            return False, round((time.perf_counter() - start_time) * 1000, 2)
            
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    def check_url(self, url: str) -> Tuple[bool, float]:
        """检测单个URL"""
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')
            timeout = Config.TIMEOUT_CHECK
            
            if url.startswith(("http://", "https://")):
                return self.check_http_url(encoded_url, timeout)
                
            elif url.startswith(("rtmp://", "rtsp://")):
                return self.check_rtmp_rtsp_url(encoded_url, timeout)
                
            else:
                start_time = time.perf_counter()
                parsed = urlparse(url)
                
                if not parsed.hostname:
                    return False, round((time.perf_counter() - start_time) * 1000, 2)
                
                port = parsed.port or 80
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(Config.TIMEOUT_CONNECT)
                sock.connect((parsed.hostname, port))
                sock.close()
                
                elapsed = (time.perf_counter() - start_time) * 1000
                return True, round(elapsed, 2)
                
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    def batch_check(self, lines: List[str]) -> Tuple[List[Tuple[str, float]], List[str]]:
        """
        批量检测
        
        Returns:
            success: 所有白名单 + 有效非白名单 [(行, 响应时间)]
            failed: 仅非白名单失败链接 [行]
        """
        success = []
        failed = []
        
        logger.info(f"开始检测 {len(lines)} 个链接的有效性")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # 提交所有任务
            futures = {}
            for line in lines:
                if ',' in line:
                    _, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (line, url)
            
            processed = 0
            
            for future in as_completed(futures):
                line, url = futures[future]
                processed += 1
                
                try:
                    is_valid, resp_time = future.result()
                    
                    # 白名单处理：无论是否有效都加入success
                    if url in self.whitelist_urls:
                        if is_valid:
                            success.append((line, resp_time))
                        else:
                            # 白名单失败：响应时间设为0.00，不加入failed
                            success.append((line, 0.00))
                            logger.warning(f"白名单链接检测失败，设为0.00ms: {url}")
                    
                    # 非白名单：有效加入success，无效加入failed
                    elif is_valid:
                        success.append((line, resp_time))
                    else:
                        failed.append(line)
                        
                except Exception as e:
                    # 异常处理
                    if url in self.whitelist_urls:
                        success.append((line, 0.00))
                        logger.error(f"白名单链接检测异常，设为0.00ms: {url}")
                    else:
                        failed.append(line)
                
                # 进度显示
                if processed % 100 == 0 or processed == len(lines):
                    valid_count = sum(1 for _, t in success if t > 0)
                    logger.info(f"进度: {processed}/{len(lines)} | 有效: {valid_count} | 白名单失败: {len(success)-valid_count} | 无效: {len(failed)}")
        
        # 按响应时间排序（0.00的会在最前面）
        success_sorted = sorted(success, key=lambda x: x[1])
        
        # 统计
        valid_count = sum(1 for _, t in success_sorted if t > 0)
        logger.info(f"检测完成 - 有效: {valid_count} | 白名单失败: {len(success_sorted)-valid_count} | 无效: {len(failed)}")
        
        return success_sorted, failed

    def save_results(self, success: List[Tuple[str, float]], failed: List[str]):
        """保存结果（保持原有文件结构）"""
        # 北京时间
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"

        # 1. 带响应时间的白名单结果（所有白名单 + 有效非白名单）
        success_resp = [
            "更新时间,#genre#", 
            version, 
            "", 
            "RespoTime,whitelist,#genre#"
        ]
        success_resp.extend([f"{resp_time:.2f}ms,{line}" for line, resp_time in success])
        
        # 2. 纯净列表（所有白名单 + 有效非白名单）
        success_clean = [
            "更新时间,#genre#", 
            version, 
            "", 
            "whitelist,#genre#"
        ]
        success_clean.extend([line for line, _ in success])
        
        # 3. 失败列表（仅非白名单）
        failed_clean = [
            "更新时间,#genre#", 
            version, 
            "", 
            "blacklist,#genre#"
        ]
        failed_clean.extend(failed)

        # 写入文件
        self._write_file(FILE_PATHS["whitelist_respotime"], success_resp)
        self._write_file(FILE_PATHS["whitelist_auto"], success_clean)
        self._write_file(FILE_PATHS["blacklist_auto"], failed_clean)
        
        logger.info(f"结果已保存")
        logger.info(f"  - {FILE_PATHS['whitelist_respotime']}: 带响应时间")
        logger.info(f"  - {FILE_PATHS['whitelist_auto']}: 纯净列表")
        logger.info(f"  - {FILE_PATHS['blacklist_auto']}: 失败链接")

    def _write_file(self, file_path: str, data: List[str]):
        """写入文件"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")

    def run(self):
        """运行检测"""
        logger.info("=" * 50)
        logger.info("直播源响应时间检测工具")
        logger.info("=" * 50)
        
        # 1. 加载白名单
        self.load_whitelist()
        
        # 2. 拉取远程源列表
        remote_urls = self.read_txt(FILE_PATHS["urls"])
        if not remote_urls:
            logger.error("没有找到远程源URL列表")
            return
        
        # 3. 拉取远程源
        all_lines = self.fetch_remote_urls(remote_urls)
        
        # 4. 确保白名单被检测
        all_lines.extend(self.whitelist_lines)
        
        # 5. 清洗去重
        cleaned_lines = self.clean_deduplicate(all_lines)
        
        if not cleaned_lines:
            logger.warning("没有需要检测的链接")
            return
        
        # 6. 批量检测
        success, failed = self.batch_check(cleaned_lines)
        
        # 7. 保存结果
        self.save_results(success, failed)
        
        # 8. 统计信息
        elapsed = datetime.now() - self.start_time
        valid_count = sum(1 for _, t in success if t > 0)
        
        logger.info("=" * 50)
        logger.info("检测完成")
        logger.info(f"总耗时: {elapsed.total_seconds():.1f} 秒")
        logger.info(f"有效链接: {valid_count} 个")
        logger.info(f"白名单失败(0.00ms): {len(success)-valid_count} 个")
        logger.info(f"无效链接: {len(failed)} 个")
        logger.info("=" * 50)


if __name__ == "__main__":
    checker = StreamChecker()
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("检测被用户中断")
    except Exception as e:
        logger.error(f"检测出错: {e}", exc_info=True)
    finally:
        logger.info("检测结束")

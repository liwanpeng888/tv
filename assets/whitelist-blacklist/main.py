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
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PotPlayer/1.7.21098"
    USER_AGENT_URL = "okhttp/3.14.9"
    
    TIMEOUT_FETCH = 5
    TIMEOUT_CHECK = 2.5
    TIMEOUT_CONNECT = 1.5
    TIMEOUT_READ = 1.5
    
    MAX_WORKERS = 16
    MAX_RETRIES = 0

class AccurateStreamChecker:
    def __init__(self):
        self.start_time = datetime.now()
        self.ipv6_available = self._check_ipv6_support()

    def _check_ipv6_support(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('2001:4860:4860::8888', 53))
            sock.close()
            return result == 0
        except:
            return False

    def read_txt(self, file_path: str) -> List[str]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []

    def create_ssl_context(self):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        return context

    def check_http_url(self, url: str, timeout: int) -> Tuple[bool, float]:
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
            return e.code in [302, 403, 404], round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Tuple[bool, float]:
        start_time = time.perf_counter()
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                elapsed = (time.perf_counter() - start_time) * 1000
                return False, round(elapsed, 2)
            port = parsed.port or (1935 if url.startswith('rtmp') else 554)
            
            addr_info = socket.getaddrinfo(parsed.hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
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
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return True, round(elapsed, 2)
                except:
                    continue
                finally:
                    if sock:
                        sock.close()
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)
        except:
            elapsed = (time.perf_counter() - start_time) * 1000
            return False, round(elapsed, 2)

    def check_url(self, url: str) -> Tuple[bool, float]:
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
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return False, round(elapsed, 2)
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

    def fetch_remote_urls(self, urls: List[str]) -> List[str]:
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
                        lines = self._parse_m3u(content)
                    else:
                        lines = [line.strip() for line in content.split('\n') if line.strip() and '://' in line and ',' in line]
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取 {len(lines)} 个候选链接")
            except Exception as e:
                logger.error(f"拉取远程源失败 {url}: {e}")
        return all_lines

    def _parse_m3u(self, content: str) -> List[str]:
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
        return lines

    def clean_deduplicate(self, lines: List[str]) -> List[str]:
        seen_urls = set()
        cleaned = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            name, url = line.split(',', 1)
            url = url.strip().split('#')[0].split('$')[0]
            if url not in seen_urls:
                seen_urls.add(url)
                cleaned.append(f"{name},{url}")
        logger.info(f"清洗去重后剩余 {len(cleaned)} 个待检测链接")
        return cleaned

    def batch_check(self, lines: List[str], whitelist: Set[str]) -> Tuple[List[Tuple[str, float]], List[str]]:
        success = []
        failed = []
        logger.info(f"开始检测 {len(lines)} 个链接的有效性")

        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
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
                    if url in whitelist:
                        success.append((line, 0.00))
                    elif is_valid:
                        success.append((line, resp_time))
                    else:
                        failed.append(line)
                except:
                    failed.append(line)
                
                if processed % 100 == 0 or processed == len(lines):
                    logger.info(f"进度: {processed}/{len(lines)} | 有效: {len(success)} | 无效: {len(failed)}")

        success_sorted = sorted(success, key=lambda x: x[1])
        logger.info(f"有效性检测完成 - 有效链接 {len(success)} 个 | 无效链接 {len(failed)} 个")
        return success_sorted, failed

    def save_results(self, success: List[Tuple[str, float]], failed: List[str]):
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"

        success_resp = [
            "更新时间,#genre#", version, "", "RespoTime,whitelist,#genre#"
        ] + [f"{resp_time:.2f}ms,{line}" for line, resp_time in success]
        
        success_clean = [
            "更新时间,#genre#", version, "", "whitelist,#genre#"
        ] + [line for line, _ in success]
        
        failed_clean = [
            "更新时间,#genre#", version, "", "blacklist,#genre#"
        ] + failed

        self._write_file(FILE_PATHS["whitelist_respotime"], success_resp)
        self._write_file(FILE_PATHS["whitelist_auto"], success_clean)
        self._write_file(FILE_PATHS["blacklist_auto"], failed_clean)
        logger.info(f"有效性检测结果已保存")

    def _write_file(self, file_path: str, data: List[str]):
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")

    def run(self):
        logger.info("===== 链接有效性检测开始 =====")
        
        remote_urls = self.read_txt(FILE_PATHS["urls"])
        all_lines = self.fetch_remote_urls(remote_urls)
        
        whitelist_lines = self.clean_deduplicate(self.read_txt(FILE_PATHS["whitelist_manual"]))
        whitelist = set()
        for line in whitelist_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                whitelist.add(url.strip())
        logger.info(f"白名单有效链接数: {len(whitelist)}")
        
        cleaned_lines = self.clean_deduplicate(all_lines)
        
        valid_links, invalid_links = self.batch_check(cleaned_lines, whitelist)
        
        self.save_results(valid_links, invalid_links)
        
        elapsed = datetime.now() - self.start_time
        logger.info("===== 链接有效性检测完成 =====")
        logger.info(f"总耗时: {elapsed.total_seconds():.1f} 秒")
        logger.info(f"最终有效链接: {len(valid_links)} 个 | 无效链接: {len(invalid_links)} 个")

if __name__ == "__main__":
    checker = AccurateStreamChecker()
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("检测被用户中断")
    except Exception as e:
        logger.error(f"检测出错: {e}", exc_info=True)
    finally:
        logger.info("检测结束")

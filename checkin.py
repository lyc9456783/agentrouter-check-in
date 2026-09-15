#!/usr/bin/env python3
"""
AgentRouter.org 自动签到脚本（纯HTTP直连版）
- 核心发现：官方备用域名 ps.air-outer.com 无 WAF 拦截，国内/机房均可直连
- 不再需要 Playwright 浏览器，纯 httpx 请求即可
- 签到接口兼容尝试：先 POST /api/user/sign_in，404 则降级 GET /api/user/sign_in
- 配置格式与之前完全一致（AGENTROUTER_ACCOUNTS: session + api_user），无需改动 secret
"""

import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv

from notify import notify

load_dotenv()

# 备用域名（无WAF），可通过环境变量覆盖
BASE_URL = os.getenv('AGENTROUTER_BASE_URL', 'https://ps.air-outer.com')
BALANCE_HASH_FILE = 'balance_hash.txt'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Referer': BASE_URL + '/',
    'Origin': BASE_URL,
}


def load_accounts():
    """从环境变量加载多账号配置"""
    accounts_str = os.getenv('AGENTROUTER_ACCOUNTS')
    if not accounts_str:
        print('ERROR: AGENTROUTER_ACCOUNTS environment variable not found')
        return None

    try:
        accounts_data = json.loads(accounts_str)

        if not isinstance(accounts_data, list):
            print('ERROR: Account configuration must use array format [{}]')
            return None

        for i, account in enumerate(accounts_data):
            if not isinstance(account, dict):
                print(f'ERROR: Account {i + 1} configuration format is incorrect')
                return None
            if 'cookies' not in account or 'api_user' not in account:
                print(f'ERROR: Account {i + 1} missing required fields (cookies, api_user)')
                return None
            if 'name' in account and not account['name']:
                print(f'ERROR: Account {i + 1} name field cannot be empty')
                return None

        return accounts_data
    except Exception as e:
        print(f'ERROR: Account configuration format is incorrect: {e}')
        return None


def load_balance_hash():
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_balance_hash(balance_hash):
    try:
        with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
            f.write(balance_hash)
    except Exception as e:
        print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
    simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def get_account_display_name(account_info, account_index):
    return account_info.get('name', f'Account {account_index + 1}')


def parse_cookies(cookies_data):
    if isinstance(cookies_data, dict):
        return cookies_data
    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


def parse_json_safe(text):
    """严格 JSON 解析：非 JSON 一律返回 None"""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def is_success(sign_j):
    """判定签到响应是否成功（兼容各种返回结构）"""
    if not isinstance(sign_j, dict):
        return False
    if sign_j.get('success') is True or sign_j.get('ret') == 1 or sign_j.get('code') == 0:
        return True
    msg = str(sign_j.get('message') or sign_j.get('msg') or '')
    # 已签到/重复签到也算成功
    if any(kw in msg for kw in ('已签到', '已经签到', 'already', 'Already', '重复')):
        return True
    return False


def check_in_account(account_info, account_index):
    """单个账号签到：纯 HTTP 直连备用域名"""
    account_name = get_account_display_name(account_info, account_index)
    print(f'\n[PROCESSING] Starting to process {account_name}')

    cookies_data = parse_cookies(account_info.get('cookies', {}))
    api_user = str(account_info.get('api_user', ''))

    if not api_user or not cookies_data:
        print(f'[FAILED] {account_name}: api_user or cookies missing')
        return False, None

    headers = dict(HEADERS)
    headers['new-api-user'] = api_user

    with httpx.Client(base_url=BASE_URL, headers=headers, cookies=cookies_data,
                      timeout=30, follow_redirects=True) as client:
        # ---- 第 1 步：验证 session 是否有效，顺便拿余额 ----
        try:
            r = client.get('/api/user/self')
        except Exception as e:
            print(f'[FAILED] {account_name}: network error - {e}')
            return False, None

        self_j = parse_json_safe(r.text)
        user_info = {'success': False}
        if self_j is None:
            preview = r.text[:80].replace('\n', ' ')
            print(f'[FAILED] {account_name}: /api/user/self non-JSON response HTTP {r.status_code}: {preview}')
            return False, None
        if self_j.get('success') is not True:
            msg = self_j.get('message', 'Unknown error')
            print(f'[FAILED] {account_name}: session invalid or expired - {msg}')
            print(f'[FAILED] {account_name}: 请重新抓取 session cookie 并更新 AGENTROUTER_ACCOUNTS')
            user_info['error'] = f'session失效: {msg}'
            return False, user_info

        d = self_j.get('data') or {}
        quota = round(d.get('quota', 0) / 500000, 2)
        used = round(d.get('used_quota', 0) / 500000, 2)
        user_info = {
            'success': True, 'quota': quota, 'used_quota': used,
            'display': f'Current balance: ${quota}, Used: ${used}',
        }
        print(f'[INFO] {account_name}: session valid. {user_info["display"]}')

        # ---- 第 2 步：签到（先 POST，404 则降级 GET） ----
        r = client.post('/api/user/sign_in')
        sign_j = parse_json_safe(r.text)
        if r.status_code == 404 and sign_j is None:
            print(f'[INFO] {account_name}: POST sign_in not found (404), trying GET...')
            r = client.get('/api/user/sign_in')
            sign_j = parse_json_safe(r.text)

        if sign_j is None:
            preview = r.text[:80].replace('\n', ' ')
            print(f'[FAILED] {account_name}: sign_in non-JSON response HTTP {r.status_code}: {preview}')
            return False, user_info

        if is_success(sign_j):
            msg = sign_j.get('message') or sign_j.get('msg') or 'OK'
            print(f'[SUCCESS] {account_name}: Check-in successful! ({msg})')
            return True, user_info

        msg = sign_j.get('message') or sign_j.get('msg') or r.text[:120]
        print(f'[FAILED] {account_name}: Check-in failed - {msg}')
        user_info['error'] = f'签到失败: {msg}'
        return False, user_info


def main():
    print('[SYSTEM] AgentRouter.org multi-account auto check-in started (direct HTTP)')
    print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print(f'[INFO] Base URL: {BASE_URL}')

    accounts = load_accounts()
    if not accounts:
        print('[FAILED] Unable to load account configuration, program exits')
        sys.exit(1)

    print(f'[INFO] Found {len(accounts)} account configurations')

    last_balance_hash = load_balance_hash()

    success_count = 0
    total_count = len(accounts)
    notification_content = []
    current_balances = {}
    need_notify = False
    balance_changed = False

    for i, account in enumerate(accounts):
        account_key = f'account_{i + 1}'
        try:
            success, user_info = check_in_account(account, i)
            if success:
                success_count += 1
            else:
                need_notify = True
                account_name = get_account_display_name(account, i)
                account_result = f'[FAIL] {account_name}'
                if user_info and user_info.get('success'):
                    account_result += f'\n{user_info["display"]}'
                elif user_info:
                    account_result += f'\n{user_info.get("error", "Unknown error")}'
                notification_content.append(account_result)

            if user_info and user_info.get('success'):
                current_balances[account_key] = {'quota': user_info['quota'], 'used': user_info['used_quota']}

        except Exception as e:
            account_name = get_account_display_name(account, i)
            print(f'[FAILED] {account_name} processing exception: {e}')
            need_notify = True
            notification_content.append(f'[FAIL] {account_name} exception: {str(e)[:50]}...')

    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    if current_balance_hash:
        if last_balance_hash is None:
            balance_changed = True
            need_notify = True
            print('[NOTIFY] First run detected, will send notification with current balances')
        elif current_balance_hash != last_balance_hash:
            balance_changed = True
            need_notify = True
            print('[NOTIFY] Balance changes detected, will send notification')
        else:
            print('[INFO] No balance changes detected')

    if balance_changed:
        for i, account in enumerate(accounts):
            account_key = f'account_{i + 1}'
            if account_key in current_balances:
                account_name = get_account_display_name(account, i)
                account_result = f'[BALANCE] {account_name}'
                account_result += f'\n:money: Current balance: ${current_balances[account_key]["quota"]}, Used: ${current_balances[account_key]["used"]}'
                if not any(account_name in item for item in notification_content):
                    notification_content.append(account_result)

    if current_balance_hash:
        save_balance_hash(current_balance_hash)

    if need_notify and notification_content:
        summary = [
            '[STATS] Check-in result statistics:',
            f'[SUCCESS] Success: {success_count}/{total_count}',
            f'[FAIL] Failed: {total_count - success_count}/{total_count}',
        ]
        if success_count == total_count:
            summary.append('[SUCCESS] All accounts check-in successful!')
        elif success_count > 0:
            summary.append('[WARN] Some accounts check-in successful')
        else:
            summary.append('[ERROR] All accounts check-in failed')

        time_info = f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        notify_content = '\n\n'.join([time_info, '\n'.join(notification_content), '\n'.join(summary)])
        print(notify_content)
        notify.push_message('AgentRouter Check-in Alert', notify_content, msg_type='text')
        print('[NOTIFY] Notification sent due to failures or balance changes')
    else:
        print('[INFO] All accounts successful and no balance changes detected, notification skipped')

    sys.exit(0 if success_count > 0 else 1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n[WARNING] Program interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'\n[FAILED] Error occurred during program execution: {e}')
        sys.exit(1)

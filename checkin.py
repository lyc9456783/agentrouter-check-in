#!/usr/bin/env python3
"""
AgentRouter.org 自动签到脚本（修复版）
- API 调用全部改为在 Playwright 浏览器内执行（page.evaluate + fetch），
  由真实浏览器环境通过阿里云 WAF 的 JS 挑战，不再被拦截页糊脸
- 修掉"响应文本包含 success 字样即判成功"的误判逻辑：
  非 JSON 响应一律视为失败（原来会被 WAF 拦截页骗成假成功）
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv
from playwright.async_api import async_playwright

from notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


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
	"""加载余额hash"""
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def save_balance_hash(balance_hash):
	"""保存余额hash"""
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
	"""生成余额数据的hash"""
	simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
	balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def get_account_display_name(account_info, account_index):
	"""获取账号显示名称"""
	return account_info.get('name', f'Account {account_index + 1}')


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
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
	"""严格 JSON 解析：解析失败返回 None（绝不拿 HTML 拦截页凑数）"""
	if not text:
		return None
	try:
		return json.loads(text)
	except Exception:
		return None


async def check_in_account(account_info, account_index):
	"""为单个账号执行签到操作：全程在真实浏览器内完成，天然过 WAF"""
	account_name = get_account_display_name(account_info, account_index)
	print(f'\n[PROCESSING] Starting to process {account_name}')

	cookies_data = parse_cookies(account_info.get('cookies', {}))
	api_user = account_info.get('api_user', '')

	if not api_user:
		print(f'[FAILED] {account_name}: API user identifier not found')
		return False, None
	if not cookies_data:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	async with async_playwright() as p:
		import tempfile
		with tempfile.TemporaryDirectory() as temp_dir:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=temp_dir,
				headless=False,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

			# 先把用户的 session cookie 注入浏览器，再访问页面
			cookie_list = []
			for k, v in cookies_data.items():
				cookie_list.append({'name': k, 'value': v, 'domain': 'agentrouter.org', 'path': '/'})
			await context.add_cookies(cookie_list)

			page = await context.new_page()
			try:
				print(f'[PROCESSING] {account_name}: Step 1: Access site to pass WAF...')
				await page.goto('https://agentrouter.org/login', wait_until='networkidle')
				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)
				# 多给 WAF 的 JS 挑战一点执行时间
				await page.wait_for_timeout(3000)

				print(f'[NETWORK] {account_name}: Executing check-in inside browser...')
				api_result = await page.evaluate(
					"""
					async (apiUser) => {
						const out = {};
						const headers = {
							'new-api-user': String(apiUser),
							'Content-Type': 'application/json',
						};
						try {
							const r = await fetch('/api/user/self', {headers, credentials: 'include'});
							out.selfStatus = r.status;
							out.selfText = await r.text();
						} catch (e) { out.selfError = String(e); }
						try {
							const r = await fetch('/api/user/sign_in', {
								method: 'POST', headers, credentials: 'include',
							});
							out.signStatus = r.status;
							out.signText = await r.text();
						} catch (e) { out.signError = String(e); }
						return out;
					}
					""",
					api_user,
				)
			except Exception as e:
				print(f'[FAILED] {account_name}: Browser flow error - {str(e)[:120]}')
				await context.close()
				return False, None
			finally:
				try:
					await context.close()
				except Exception:
					pass

	# ---- 严格解析：非 JSON 一律失败 ----
	self_text = api_result.get('selfText') or ''
	sign_text = api_result.get('signText') or ''

	self_j = parse_json_safe(self_text)
	user_info = {'success': False}
	if self_j is None:
		preview = (self_text or api_result.get('selfError') or '')[:80].replace('\n', ' ')
		user_info['error'] = f'用户信息接口非JSON(WAF拦截?) {preview}'
		print(f'[WARN] {account_name}: {user_info["error"]}')
	elif self_j.get('success') is True:
		d = self_j.get('data') or {}
		quota = round(d.get('quota', 0) / 500000, 2)
		used = round(d.get('used_quota', 0) / 500000, 2)
		user_info = {
			'success': True, 'quota': quota, 'used_quota': used,
			'display': f'Current balance: ${quota}, Used: ${used}',
		}
		print(f'[INFO] {account_name}: {user_info["display"]}')
	else:
		user_info['error'] = f'用户信息接口: {self_j.get("message", "Unknown error")}'
		print(f'[WARN] {account_name}: {user_info["error"]}')

	sign_j = parse_json_safe(sign_text)
	if sign_j is None:
		preview = (sign_text or api_result.get('signError') or '')[:80].replace('\n', ' ')
		print(f'[FAILED] {account_name}: 签到响应不是JSON(WAF拦截页)，签到未执行: {preview}')
		return False, user_info

	if sign_j.get('success') is True or sign_j.get('ret') == 1 or sign_j.get('code') == 0:
		print(f'[SUCCESS] {account_name}: Check-in successful!')
		return True, user_info

	print(f'[FAILED] {account_name}: Check-in failed - {sign_j.get("msg") or sign_j.get("message") or sign_text[:120]}')
	return False, user_info


async def main():
	"""主函数"""
	print('[SYSTEM] AgentRouter.org multi-account auto check-in started (browser-based)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

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
			success, user_info = await check_in_account(account, i)
			if success:
				success_count += 1
			else:
				need_notify = True
				account_name = get_account_display_name(account, i)
				status = '[SUCCESS]' if success else '[FAIL]'
				account_result = f'{status} {account_name}'
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


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
订阅URL生成工具
功能：将高质量节点转换为可订阅的URL链接
"""

import os
import base64
import requests
from loguru import logger


class SubscriptionURLGenerator:
    def __init__(self):
        # 建议使用拥有 Gist 权限的 Personal Access Token
        self.github_token = os.getenv('GIST_TOKEN') or os.getenv('GITHUB_TOKEN')
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

    # -------------------------------------------------
    # 1️⃣ 创建/更新 Gist（写入 Base64 与明文两文件）
    # -------------------------------------------------
    def create_or_update_github_gist(self, nodes_file, description="High Quality Proxy Nodes"):
        """
        创建或更新 GitHub Gist 并返回两个永久 raw 链接：
            txt_url  – subscription.txt （Base64）
            yaml_url – subscription.yaml（明文）
        """
        if not self.github_token:
            logger.warning('⚠️ 未配置 GIST_TOKEN / GITHUB_TOKEN，无法创建/更新 Gist')
            return None

        try:
            # ---------- 读取节点 ----------
            with open(nodes_file, 'r', encoding='utf-8') as f:
                nodes_content = f.read()

            # ---------- 生成 Base64 ----------
            b64_content = base64.b64encode(nodes_content.encode('utf-8')).decode('utf-8')

            # ---------- 准备要写入 Gist 的两个文件 ----------
            gist_files = {
                'subscription.txt':   {'content': b64_content},
                'subscription.yaml': {'content': nodes_content}
            }

            # ---------- HTTP Header ----------
            headers = {
                'Authorization': f'token {self.github_token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            # ---------- 获取已有 Gist ID ----------
            gist_id_file = os.path.join(os.path.dirname(nodes_file), '.gist_id')
            existing_gist_id = os.getenv('GIST_ID')
            if not existing_gist_id and os.path.exists(gist_id_file):
                try:
                    with open(gist_id_file, 'r', encoding='utf-8') as f:
                        existing_gist_id = f.read().strip()
                    logger.info(f'📝 发现本地 Gist ID: {existing_gist_id[:8]}...')
                except Exception:
                    pass
            elif existing_gist_id:
                logger.info(f'📝 使用环境变量 GIST_ID: {existing_gist_id[:8]}...')

            # ---------- 1️⃣ 尝试更新已有 Gist ----------
            if existing_gist_id:
                update_url = f'https://api.github.com/gists/{existing_gist_id}'
                update_data = {
                    'description': description,
                    'files': gist_files
                }
                response = requests.patch(update_url, json=update_data,
                                          headers=headers, timeout=10)
                if response.status_code == 200:
                    result = response.json()
                    raw_url = result['files']['subscription.txt']['raw_url']
                    txt_url = raw_url.split('/raw/')[0] + '/raw/subscription.txt'
                    yaml_url = raw_url.split('/raw/')[0] + '/raw/subscription.yaml'

                    logger.info('✅ Gist 更新成功 (复用已有链接)')
                    logger.info(f'   Gist 页面: {result["html_url"]}')
                    logger.info(f'   Base64 订阅 URL（永久）: {txt_url}')
                    logger.info(f'   明文 YAML 订阅 URL（永久）: {yaml_url}')
                    return txt_url, yaml_url
                else:
                    logger.warning(f'⚠️ Gist 更新失败 (HTTP {response.status_code})，将创建新的 Gist')
                    existing_gist_id = None  # 失效后改为新建

            # ---------- 2️⃣ 创建新的 Gist ----------
            create_url = 'https://api.github.com/gists'
            create_data = {
                'description': description,
                'public': False,   # 私密 Gist
                'files': gist_files
            }
            response = requests.post(create_url, json=create_data,
                                     headers=headers, timeout=10)
            if response.status_code == 201:
                result = response.json()
                gist_id = result['id']
                raw_url = result['files']['subscription.txt']['raw_url']
                txt_url = raw_url.split('/raw/')[0] + '/raw/subscription.txt'
                yaml_url = raw_url.split('/raw/')[0] + '/raw/subscription.yaml'

                # 保存 Gist ID，以便下次更新
                try:
                    with open(gist_id_file, 'w', encoding='utf-8') as f:
                        f.write(gist_id)
                    logger.info(f'💾 已保存 Gist ID 到 {gist_id_file}')
                except Exception as e:
                    logger.warning(f'⚠️ 保存 Gist ID 失败: {e}')

                logger.info('✅ Gist 创建成功 (包含 subscription.txt 与 subscription.yaml)')
                logger.info(f'   Gist ID: {gist_id}')
                logger.info(f'   Base64 订阅 URL（永久）: {txt_url}')
                logger.info(f'   明文 YAML 订阅 URL（永久）: {yaml_url}')
                return txt_url, yaml_url
            else:
                logger.error(f'❌ Gist 创建失败: HTTP {response.status_code}')
                logger.error(f'   {response.text}')
                return None
        except Exception as e:
            logger.error(f'❌ Gist 操作异常: {e}')
            return None

    # -------------------------------------------------
    # 2️⃣ 通过公开转换服务生成各类订阅链接
    # -------------------------------------------------
    def create_subscription_with_converter(self, nodes_file):
        """
        调用公开的订阅转换 API，返回一个列表，
        每个元素包含 clash / surge / v2ray 三种格式的链接
        """
        try:
            with open(nodes_file, 'r', encoding='utf-8') as f:
                nodes_content = f.read()
            b64_content = base64.b64encode(nodes_content.encode('utf-8')).decode('utf-8')

            converters = [
                'https://api.dler.io',
                'https://sub.xeton.dev',
                'https://api.v1.mk'
            ]

            subscription_urls = []
            for converter in converters:
                sub_url = f"{converter}/sub?target=clash&url={b64_content}"
                subscription_urls.append({
                    'backend': converter,
                    'clash_url': sub_url,
                    'surge_url': f"{converter}/sub?target=surge&url={b64_content}",
                    'v2ray_url': f"{converter}/sub?target=v2ray&url={b64_content}"
                })
            return subscription_urls
        except Exception as e:
            logger.error(f'❌ 订阅 URL 创建失败: {e}')
            return []

    # -------------------------------------------------
    # 3️⃣ 生成所有方案并（可选）推送到 Telegram
    # -------------------------------------------------
    def send_subscription_urls_to_telegram(self, nodes_file):
        """
        生成订阅 URL 并发送到 Telegram
        如果未配置 Telegram，则只生成文件（降级方案）
        """
        logger.info('=' * 60)
        logger.info('🔗 生成订阅 URL')
        logger.info('=' * 60)

        # ---------- 文件是否存在 ----------
        if not os.path.exists(nodes_file):
            logger.error(f'❌ 节点文件不存在: {nodes_file}')
            return

        # ---------- Telegram 配置 ----------
        has_telegram = bool(self.telegram_bot_token and self.telegram_chat_id)
        if not has_telegram:
            logger.warning('⚠️ 未配置 Telegram Bot，将只生成本地文件（降级模式）')

        # ---------- 统计节点数 ----------
        with open(nodes_file, 'r', encoding='utf-8') as f:
            node_count = len([line for line in f if line.strip()])
        logger.info(f'📊 节点总数: {node_count} 个')

        message_parts = []
        if has_telegram:
            message_parts = [
                "🔗 *订阅 URL 已生成*\n",
                f"📊 节点总数: {node_count} 个\n",
                "━━━━━━━━━━━━━━━━━━━━\n"
            ]

        # ------------------- 方案 1：GitHub Gist -------------------
        logger.info('\n📌 方案1: 创建/更新 GitHub Gist 订阅...')
        gist_res = self.create_or_update_github_gist(nodes_file)   # 返回 tuple 或 None
        if gist_res:
            txt_url, yaml_url = gist_res
            message_parts.append("\n*方案1: GitHub Gist 订阅* ⭐ 推荐\n")
            message_parts.append(f"- Base64 版  : `{txt_url}`\n")
            message_parts.append(f"- 明文 YAML版: `{yaml_url}`\n")
            message_parts.append("\n💡 *使用方法*:\n")
            message_parts.append("直接复制对应 URL 到代理客户端订阅\n")
            message_parts.append("• 私密链接，仅知道 URL 的人可访问\n")
            message_parts.append("• GitHub CDN 加速，全球访问快速\n")
            message_parts.append("• 支持所有客户端\n")
        else:
            logger.warning('⚠️ Gist 生成失败，方案1 将被略过')

        # ------------------- 方案 2：订阅转换 -------------------
        logger.info('\n📌 方案2: 生成订阅转换 URL...')
        sub_urls = self.create_subscription_with_converter(nodes_file)
        if sub_urls:
            message_parts.append("\n━━━━━━━━━━━━━━━━━━━━\n")
            message_parts.append("\n*方案2: 订阅转换服务*\n")
            message_parts.append("\n🔸 *Clash 订阅*:\n")
            for i, item in enumerate(sub_urls, 1):
                backend_name = item['backend'].split('//')[1].split('/')[0]
                message_parts.append(f"{i}. 后端: `{backend_name}`\n")
            message_parts.append("\n💡 *提示*:\n")
            message_parts.append("URL 较长，已保存到附件文件，需下载查看完整链接\n")

        # ------------------- 方案 3：Base64 原始 -------------------
        logger.info('\n📌 方案3: 生成 Base64 原始订阅...')
        with open(nodes_file, 'r', encoding='utf-8') as f:
            nodes_content = f.read()
        b64_content = base64.b64encode(nodes_content.encode('utf-8')).decode('utf-8')
        message_parts.append("\n━━━━━━━━━━━━━━━━━━━━\n")
        message_parts.append("\n*方案3: Base64 订阅*\n")
        message_parts.append("已生成 Base64 编码文件，可配合任意转换服务使用\n")

        # ------------------- 发送 Telegram 文本 -------------------
        if has_telegram:
            message = ''.join(message_parts)
            self._send_telegram_message(message)

        # ------------------- 写入本地文件（始终生成） -------------------
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'runtime')
        os.makedirs(output_dir, exist_ok=True)
        urls_file = os.path.join(output_dir, 'high_quality_nodes_urls.txt')

        with open(urls_file, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("高质量节点订阅 URL 清单\n")
            f.write("=" * 60 + "\n\n")

            if gist_res:
                f.write("【方案1】GitHub Gist 订阅（推荐）\n")
                f.write("-" * 60 + "\n")
                f.write(f"Base64 订阅 URL: {txt_url}\n")
                f.write(f"明文 YAML 订阅 URL: {yaml_url}\n\n")
                f.write("优势:\n")
                f.write("  ✓ 私密链接，只有知道 URL 的人才能访问\n")
                f.write("  ✓ GitHub CDN 加速，全球访问快速\n")
                f.write("  ✓ 支持所有代理客户端\n")
                f.write("  ✓ 直接使用，无需额外转换\n\n")

            if sub_urls:
                f.write("【方案2】订阅转换服务\n")
                f.write("-" * 60 + "\n\n")
                for i, item in enumerate(sub_urls, 1):
                    backend_name = item['backend'].split('//')[1].split('/')[0]
                    f.write(f"后端 {i}: {backend_name}\n")
                    f.write(f"  Clash 订阅: {item['clash_url']}\n")
                    f.write(f"  Surge 订阅: {item['surge_url']}\n")
                    f.write(f"  V2Ray 订阅: {item['v2ray_url']}\n\n")

            f.write("\n【方案3】Base64 订阅内容\n")
            f.write("-" * 60 + "\n")
            f.write("Base64 内容（可配合任意转换 API 使用）:\n\n")
            f.write(b64_content[:100] + "...\n")
            f.write(f"\n完整内容字符数: {len(b64_content)}\n\n")
            f.write("使用方法:\n")
            f.write("  将 Base64 内容作为订阅链接或配合转换 API 使用\n")

        logger.info(f'💾 订阅 URL 文件已保存: {urls_file}')

        # ------------------- 发送文件到 Telegram -------------------
        if has_telegram:
            self._send_telegram_file(urls_file, "📋 *完整订阅 URL 清单*")
        else:
            logger.info('💡 提示: 配置 TELEGRAM_BOT_TOKEN 和 TELEGRAM_CHAT_ID 可自动推送到Telegram')

        logger.info('=' * 60)
        if has_telegram:
            logger.info('✅ 订阅 URL 已发送到 Telegram')
        else:
            logger.info('✅ 订阅 URL 文件生成完成（未配置 Telegram 推送）')
        logger.info('=' * 60)

    # -------------------------------------------------
    # 4️⃣ 私有的 Telegram 发送工具
    # -------------------------------------------------
    def _send_telegram_message(self, message):
        """发送纯文本消息到 Telegram"""
        try:
            url = f'https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage'
            data = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': True
            }
            response = requests.post(url, json=data, timeout=10)
            if response.status_code == 200:
                logger.info('✅ Telegram 消息发送成功')
            else:
                logger.warning(f'⚠️ Telegram 消息发送失败: {response.status_code}')
        except Exception as e:
            logger.error(f'❌ Telegram 消息发送异常: {e}')

    def _send_telegram_file(self, file_path, caption=""):
        """发送文件（文档）到 Telegram"""
        try:
            url = f'https://api.telegram.org/bot{self.telegram_bot_token}/sendDocument'
            with open(file_path, 'rb') as f:
                files = {'document': f}
                data = {
                    'chat_id': self.telegram_chat_id,
                    'caption': caption,
                    'parse_mode': 'Markdown'
                }
                response = requests.post(url, data=data, files=files, timeout=30)
            if response.status_code == 200:
                logger.info(f'✅ 文件已发送: {os.path.basename(file_path)}')
            else:
                logger.warning(f'⚠️ 文件发送失败: {response.status_code}')
        except Exception as e:
            logger.error(f'❌ 文件发送异常: {e}')


def main():
    """主函数 – 读取默认节点文件并生成/推送订阅"""
    import sys
    logger.remove()
    logger.add(sys.stdout, colorize=True,
               format="<green>{time:HH:mm:ss}</green> | <level>{message}</level>")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    nodes_file = os.path.join(base_dir, 'sub', 'high_quality_nodes.txt')

    generator = SubscriptionURLGenerator()
    generator.send_subscription_urls_to_telegram(nodes_file)


if __name__ == '__main__':
    main()

// src/handler.ts - 路由处理器

import type { Env } from "./types";
import { SogaAPI } from "./api/soga";
import { UserAPI } from "./api/user";
import { AdminAPI } from "./api/admin";
import { AuthAPI } from "./api/auth";
import { SubscriptionAPI } from "./api/subscription";
import { AnnouncementAPI } from "./api/announcement";
import { TrafficAPI } from "./api/traffic";
import { WalletAPI } from "./api/wallet";
import { StoreAPI } from "./api/store";
import { PaymentAPI } from "./api/pay/PaymentAPI";
import { TicketAPI } from "./api/ticket";
import { TelegramAPI } from "./api/telegram";
import { errorResponse, successResponse } from "./utils/response";
import { DatabaseService } from "./services/database";
import { validateSubscriptionDomain } from "./middleware/subscriptionAuth";

export async function handleRequest(
  request: Request,
  env: Env,
  ctx: ExecutionContext
): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 验证订阅域名访问权限（对所有请求）
  const subscriptionValidation = await validateSubscriptionDomain(request, env);
  if (!subscriptionValidation.success) {
    return subscriptionValidation.response ?? errorResponse("Access denied", 403);
  }


  // 初始化 API 实例
  const sogaAPI = new SogaAPI(env);
  const userAPI = new UserAPI(env);
  const adminAPI = new AdminAPI(env);
  const authAPI = new AuthAPI(env);
  const subscriptionAPI = new SubscriptionAPI(env);
  const announcementAPI = new AnnouncementAPI(env);
  const trafficAPI = new TrafficAPI(env);
  const walletAPI = new WalletAPI(env);
  const storeAPI = new StoreAPI(env);
  const paymentAPI = new PaymentAPI(env);
  const ticketAPI = new TicketAPI(env);
  const telegramAPI = new TelegramAPI(env);

  // 路由映射
  const routes: Record<string, () => Promise<Response> | Response> = {
    // 健康检查和测试端点
    "GET /api/health": () => getHealthStatus(env),
    "GET /api/database/test": () => testDatabaseConnection(env),
    
    // Soga 后端 API
    "GET /api/v1/node": () => sogaAPI.getNode(request),
    "GET /api/v1/users": () => sogaAPI.getUsers(request),
    "GET /api/v1/audit_rules": () => sogaAPI.getAuditRules(request),
    "GET /api/v1/xray_rules": () => sogaAPI.getXrayRules(request),
    "GET /api/v1/white_list": () => sogaAPI.getWhiteList(request),
    "POST /api/v1/traffic": () => sogaAPI.submitTraffic(request),
    "POST /api/v1/alive_ip": () => sogaAPI.submitAliveIP(request),
    "POST /api/v1/audit_log": () => sogaAPI.submitAuditLog(request),
    "POST /api/v1/status": () => sogaAPI.submitNodeStatus(request),

    // 用户认证 API
    "POST /api/auth/login": () => authAPI.login(request),
    "POST /api/auth/telegram-miniapp": () => authAPI.telegramMiniAppLogin(request),
    "POST /api/auth/google": () => authAPI.googleOAuthLogin(request),
    "POST /api/auth/github": () => authAPI.githubOAuthLogin(request),
    "POST /api/auth/register": () => authAPI.register(request),
    "POST /api/auth/logout": () => authAPI.logout(request),
    "POST /api/auth/oauth/complete": () =>
      authAPI.completePendingOAuthRegistration(request),
    "POST /api/auth/send-email-code": () => authAPI.sendEmailCode(request),
    "POST /api/auth/password-reset/request": () =>
      authAPI.requestPasswordReset(request),
    "POST /api/auth/password-reset/confirm": () =>
      authAPI.confirmPasswordReset(request),
    "GET /api/auth/register-config": () => authAPI.getRegisterConfig(),
    "POST /api/auth/verify-2fa": () => authAPI.verifyTwoFactor(request),
    "POST /api/auth/passkey/register/options": () =>
      authAPI.generatePasskeyRegistrationOptions(request),
    "POST /api/auth/passkey/register/verify": () =>
      authAPI.verifyPasskeyRegistration(request),
    "POST /api/auth/passkey/login/options": () =>
      authAPI.generatePasskeyLoginOptions(request),
    "POST /api/auth/passkey/login/verify": () =>
      authAPI.verifyPasskeyLogin(request),
    "GET /api/site/settings": () => authAPI.getSiteSettings(),

    // 用户 API
    "GET /api/user/profile": () => userAPI.getProfile(request),
    "PUT /api/user/profile": () => userAPI.updateProfile(request),
    "POST /api/user/change-password": () => userAPI.changePassword(request),
    "GET /api/user/nodes": () => userAPI.getAccessibleNodes(request),
    "GET /api/user/traffic-stats": () => userAPI.getTrafficStats(request),
    "POST /api/user/reset-subscription-token": () => userAPI.resetSubscriptionToken(request),
    "GET /api/user/subscription-logs": () => userAPI.getSubscriptionLogs(request),
    "GET /api/user/bark-settings": () => userAPI.getBarkSettings(request),
    "PUT /api/user/bark-settings": () => userAPI.updateBarkSettings(request),
    "POST /api/user/bark-test": () => userAPI.testBarkNotification(request),
    "GET /api/user/telegram-settings": () => userAPI.getTelegramSettings(request),
    "PUT /api/user/telegram-settings": () => userAPI.updateTelegramSettings(request),
    "POST /api/user/telegram-test": () => userAPI.testTelegramNotification(request),
    "POST /api/user/telegram-bind-code": () => userAPI.refreshTelegramBindCode(request),
    "POST /api/user/telegram-unbind": () => userAPI.unbindTelegram(request),
    "GET /api/user/login-logs": () => userAPI.getLoginLogs(request),
    "GET /api/user/online-devices": () => userAPI.getOnlineDevices(request),
    "GET /api/user/online-ips-detail": () => userAPI.getOnlineIpsDetail(request),
    "GET /api/user/referrals": () => userAPI.getReferralOverview(request),
    "GET /api/user/rebate/ledger": () => userAPI.getRebateLedger(request),
    "POST /api/user/rebate/transfer": () => userAPI.transferRebateToBalance(request),
    "POST /api/user/rebate/withdraw": () => userAPI.createRebateWithdrawal(request),
    "GET /api/user/rebate/withdrawals": () => userAPI.getRebateWithdrawals(request),
    "POST /api/user/two-factor/setup": () => userAPI.startTwoFactorSetup(request),
    "POST /api/user/two-factor/enable": () => userAPI.enableTwoFactor(request),
    "POST /api/user/two-factor/backup-codes": () =>
      userAPI.regenerateTwoFactorBackupCodes(request),
    "POST /api/user/two-factor/disable": () => userAPI.disableTwoFactor(request),
    "GET /api/user/passkeys": () => userAPI.listPasskeys(request),
    "DELETE /api/user/passkeys/:id": () => {
      const id = url.pathname.split("/").pop() || "";
      return userAPI.deletePasskey(request, id);
    },
    "GET /api/user/shared-ids": () => userAPI.getSharedIds(request),

    // 工单 API（用户）
    "GET /api/user/tickets": () => ticketAPI.listUserTickets(request),
    "POST /api/user/tickets": () => ticketAPI.createTicket(request),
    "GET /api/user/tickets/:id": () => ticketAPI.getUserTicketDetail(request),
    "POST /api/user/tickets/:id/replies": () => ticketAPI.replyTicketAsUser(request),
    "GET /api/user/tickets/unread-count": () => ticketAPI.getUserUnreadCount(request),
    "POST /api/user/tickets/:id/close": () => ticketAPI.closeTicketByUser(request),
    
    // 用户审计功能 API
    "GET /api/user/audit-rules": () => userAPI.getAuditRules(request),
    "GET /api/user/audit-logs": () => userAPI.getAuditLogs(request),
    "GET /api/user/audit-overview": () => userAPI.getAuditOverview(request),

    // 订阅 API
    "GET /api/subscription/v2ray": () => subscriptionAPI.getV2RaySubscription(request),
    "GET /api/subscription/clash": () => subscriptionAPI.getClashSubscription(request),
    "GET /api/subscription/quantumultx": () => subscriptionAPI.getQuantumultXSubscription(request),
    "GET /api/subscription/singbox": () => subscriptionAPI.getSingboxSubscription(request),
    "GET /api/subscription/shadowrocket": () => subscriptionAPI.getShadowrocketSubscription(request),
    "GET /api/subscription/surge": () => subscriptionAPI.getSurgeSubscription(request),

    // 基础管理员 API
    // 用户管理
    "GET /api/admin/users": () => adminAPI.getUsers(request),
    "GET /api/admin/user-stats": () => adminAPI.getUserStats(request),
    "GET /api/admin/users/export": () => adminAPI.exportUsers(request),
    "POST /api/admin/users": () => adminAPI.createUser(request),
    "PUT /api/admin/users/:id": () => adminAPI.updateUser(request),
    "POST /api/admin/users/:id/status": () => adminAPI.toggleUserStatus(request),
    "POST /api/admin/users/:id/traffic": () => adminAPI.resetUserTraffic(request),
    "DELETE /api/admin/users/:id": () => adminAPI.deleteUser(request),
    
    // 节点管理
    "GET /api/admin/nodes": () => adminAPI.getNodes(request),
    "GET /api/admin/node-stats": () => adminAPI.getNodeStats(request),
    "GET /api/admin/node-status": () => adminAPI.getNodeStatusList(request),
    "GET /api/admin/nodes/export": () => adminAPI.exportNodes(request),
    "POST /api/admin/nodes": () => adminAPI.createNode(request),
    "PUT /api/admin/nodes/:id": () => adminAPI.updateNode(request),
    "POST /api/admin/nodes/:id/traffic": () => adminAPI.resetNodeTraffic(request),
    "DELETE /api/admin/nodes/:id": () => adminAPI.deleteNode(request),
    "POST /api/admin/nodes/batch": () => adminAPI.batchUpdateNodes(request),
    // 系统管理
    "GET /api/admin/statistics": () => adminAPI.getStatistics(request),
    "GET /api/admin/statistics/export": () => adminAPI.exportStatistics(request),
    "GET /api/admin/system-health": () => adminAPI.getSystemHealth(request),
    "GET /api/admin/system-stats": () => adminAPI.getSystemStats(request),
    
    // 日志管理
    "GET /api/admin/login-logs": () => adminAPI.getLoginLogs(request),
    "GET /api/admin/subscription-logs": () => adminAPI.getSubscriptionLogs(request),
    "GET /api/admin/audit-logs": () => adminAPI.getAuditLogs(request),
    "DELETE /api/admin/login-logs/:id": () => adminAPI.deleteLoginLog(request),
    "POST /api/admin/login-logs/batch-delete": () => adminAPI.batchDeleteLoginLogs(request),
    "POST /api/admin/login-logs/export-csv": () => adminAPI.exportLoginLogsCSV(request),
    "DELETE /api/admin/subscription-logs/:id": () => adminAPI.deleteSubscriptionLog(request),
    "POST /api/admin/subscription-logs/batch-delete": () => adminAPI.batchDeleteSubscriptionLogs(request),
    "POST /api/admin/subscription-logs/export-csv": () => adminAPI.exportSubscriptionLogsCSV(request),
    "DELETE /api/admin/audit-logs/:id": () => adminAPI.deleteAuditLog(request),
    "POST /api/admin/audit-logs/batch-delete": () => adminAPI.batchDeleteAuditLogs(request),
    
    // 在线状态管理
    "GET /api/admin/online-ips": () => adminAPI.getOnlineIPs(request),
    "DELETE /api/admin/online-ips/:id": () => adminAPI.deleteOnlineIP(request),
    "POST /api/admin/online-ips/batch-delete": () => adminAPI.batchDeleteOnlineIPs(request),
    "POST /api/admin/online-ips/export-csv": () => adminAPI.exportOnlineIPsCSV(request),
    "POST /api/admin/kick-ip": () => adminAPI.kickIP(request),
    "POST /api/admin/block-ip": () => adminAPI.blockIP(request),
    
    // 审计管理
    "GET /api/admin/audit-rules": () => adminAPI.getAuditRules(request),
    "POST /api/admin/audit-rules": () => adminAPI.createAuditRule(request),
    "PUT /api/admin/audit-rules/:id": () => adminAPI.updateAuditRule(request),
    "DELETE /api/admin/audit-rules/:id": () => adminAPI.deleteAuditRule(request),
    "GET /api/admin/xray-rules": () => adminAPI.getXrayRules(request),
    "POST /api/admin/xray-rules": () => adminAPI.createXrayRule(request),
    "PUT /api/admin/xray-rules/:id": () => adminAPI.updateXrayRule(request),
    "DELETE /api/admin/xray-rules/:id": () => adminAPI.deleteXrayRule(request),
    
    // 白名单管理
    "GET /api/admin/whitelist": () => adminAPI.getWhitelist(request),
    "POST /api/admin/whitelist": () => adminAPI.createWhitelistRule(request),
    "PUT /api/admin/whitelist/:id": () => adminAPI.updateWhitelistRule(request),
    "DELETE /api/admin/whitelist/:id": () => adminAPI.deleteWhitelistRule(request),
    "POST /api/admin/whitelist/batch": () => adminAPI.batchWhitelistOperation(request),
    "GET /api/admin/shared-ids": () => adminAPI.getSharedIds(request),
    "POST /api/admin/shared-ids": () => adminAPI.createSharedId(request),
    "PUT /api/admin/shared-ids/:id": () => adminAPI.updateSharedId(request),
    "DELETE /api/admin/shared-ids/:id": () => adminAPI.deleteSharedId(request),
    
    // 定时任务管理
    "POST /api/admin/trigger-traffic-reset": () => adminAPI.triggerTrafficReset(request),
    "POST /api/admin/trigger-node-status-cleanup": () => adminAPI.triggerNodeStatusCleanup(request),
    "POST /api/admin/trigger-node-traffic-reset": () => adminAPI.triggerNodeTrafficReset(request),
    "GET /api/admin/scheduler-status": () => adminAPI.checkSchedulerStatus(request),
    
    // 管理员操作功能
    "POST /api/admin/reset-daily-traffic": () => adminAPI.resetDailyTraffic(request),
    "POST /api/admin/reset-all-passwords": () => adminAPI.resetAllUserPasswords(request),
    "POST /api/admin/reset-all-subscriptions": () => adminAPI.resetAllSubscriptionTokens(request),

    // 等级管理 API
    "POST /api/admin/check-expired-levels": () => adminAPI.checkExpiredLevels(request),
    "GET /api/admin/level-stats": () => adminAPI.getLevelStats(request),
    "POST /api/admin/set-level-expiry": () => adminAPI.setLevelExpiry(request),
    "GET /api/admin/expired-users": () => adminAPI.getExpiredUsers(request),

    // 测试数据生成 API
    "POST /api/admin/generate-traffic-test-data": () => adminAPI.generateTrafficTestData(request),

    // 公告 API
    "GET /api/announcements": () => announcementAPI.getAnnouncements(request),
    "GET /api/admin/announcements": () => announcementAPI.getAllAnnouncements(request),
    "POST /api/admin/announcements": () => announcementAPI.createAnnouncement(request),
    "PUT /api/admin/announcements/:id": () => announcementAPI.updateAnnouncement(request),
    "DELETE /api/admin/announcements/:id": () => announcementAPI.deleteAnnouncement(request),

    // 流量 API
    // 用户流量
    "GET /api/user/traffic/trends": () => trafficAPI.getUserTrafficTrends(request),
    "GET /api/user/traffic/summary": () => trafficAPI.getUserTrafficSummary(request),
    "GET /api/user/traffic-records": () => trafficAPI.getUserTrafficRecords(request),
    "POST /api/user/traffic/manual-update": () => trafficAPI.manualTrafficUpdate(request),
    // 系统流量（管理员）
    "GET /api/admin/traffic/trends": () => trafficAPI.getSystemTrafficTrends(request),
    "POST /api/admin/traffic/daily-reset": () => trafficAPI.dailyTrafficReset(request),
    "GET /api/admin/traffic/overview": () => trafficAPI.getTrafficOverview(request),

    // 系统配置管理 API
    "GET /api/admin/system-configs": () => adminAPI.getSystemConfigs(request),
    "PUT /api/admin/system-configs": () => adminAPI.updateSystemConfig(request),
    "PUT /api/admin/system-configs/batch": () => adminAPI.updateSystemConfigsBatch(request),
    "POST /api/admin/system-configs": () => adminAPI.addSystemConfig(request),
    "GET /api/admin/rebate/withdrawals": () => adminAPI.getRebateWithdrawals(request),
    "POST /api/admin/rebate/withdrawals/review": () => adminAPI.reviewRebateWithdrawal(request),
    "POST /api/admin/invite-codes/reset": () => adminAPI.resetAllInviteCodes(request),
    
    // 缓存管理 API
    "GET /api/admin/cache-status": () => adminAPI.getCacheStatus(request),
    "POST /api/admin/clear-cache/all": () => adminAPI.clearAllCache(request),
    "POST /api/admin/clear-cache/nodes": () => adminAPI.clearNodeCache(request),
    "POST /api/admin/clear-cache/audit-rules": () => adminAPI.clearAuditRulesCache(request),
    "POST /api/admin/clear-cache/whitelist": () => adminAPI.clearWhitelistCache(request),

    // 钱包相关 API
    "GET /api/wallet/money": () => walletAPI.getMoney(request),
    "GET /api/wallet/recharge-records": () => walletAPI.getRechargeRecords(request),
    "POST /api/wallet/recharge": () => walletAPI.createRecharge(request),
    "POST /api/wallet/recharge/callback": () => walletAPI.rechargeCallback(request),
    "GET /api/wallet/recharge/callback": () => walletAPI.rechargeCallback(request),
    "GET /api/wallet/stats": () => walletAPI.getWalletStats(request),
    "POST /api/wallet/gift-card/redeem": () => walletAPI.redeemGiftCard(request),

    // 商店相关 API
    "GET /api/packages": () => storeAPI.getPackages(request),
    "GET /api/packages/:id": () => storeAPI.getPackageDetail(request),
    "POST /api/packages/coupon/preview": () => storeAPI.previewCoupon(request),
    "POST /api/packages/purchase": () => storeAPI.purchasePackage(request),
    "GET /api/packages/purchase-records": () => storeAPI.getPurchaseRecords(request),

    // 支付接口 API
    "GET /api/payment/config": () => paymentAPI.getPaymentConfig(),
    "GET /api/payment/create": () => paymentAPI.createPayment(request),
    "POST /api/payment/callback": () => paymentAPI.paymentCallback(request),
    "GET /api/payment/status/:trade_no": () => paymentAPI.getPaymentStatus(request),
    "GET /api/payment/notify": () => paymentAPI.paymentNotify(request),
    "POST /api/payment/notify": () => paymentAPI.paymentNotify(request),

    // Telegram Bot Webhook
    "GET /api/telegram/webhook": () => telegramAPI.handleWebhook(request),
    "POST /api/telegram/webhook": () => telegramAPI.handleWebhook(request),

    // 管理员套餐管理 API
    "GET /api/admin/packages": () => adminAPI.getPackages(request),
    "POST /api/admin/packages": () => adminAPI.createPackage(request),
    "PUT /api/admin/packages/:id": () => adminAPI.updatePackage(request),
    "DELETE /api/admin/packages/:id": () => adminAPI.deletePackage(request),
    "GET /api/admin/coupons": () => adminAPI.getCoupons(request),
    "POST /api/admin/coupons": () => adminAPI.createCoupon(request),
    "GET /api/admin/coupons/:id": () => adminAPI.getCouponDetail(request),
    "PUT /api/admin/coupons/:id": () => adminAPI.updateCoupon(request),
    "DELETE /api/admin/coupons/:id": () => adminAPI.deleteCoupon(request),
    "GET /api/admin/gift-cards": () => adminAPI.getGiftCards(request),
    "POST /api/admin/gift-cards": () => adminAPI.createGiftCard(request),
    "PUT /api/admin/gift-cards/:id": () => adminAPI.updateGiftCard(request),
    "DELETE /api/admin/gift-cards/:id": () => adminAPI.deleteGiftCard(request),
    "POST /api/admin/gift-cards/:id/status": () => adminAPI.updateGiftCardStatus(request),
    "GET /api/admin/gift-cards/:id/redemptions": () => adminAPI.getGiftCardRedemptions(request),
    "GET /api/admin/package-stats": () => adminAPI.getPackageStats(request),
    "GET /api/admin/recharge-records": () => adminAPI.getRechargeRecords(request),
    "GET /api/admin/purchase-records": () => adminAPI.getPurchaseRecords(request),
    "POST /api/admin/recharge-records/:trade_no/mark-paid": () => adminAPI.markRechargeRecordPaid(request),
    "POST /api/admin/purchase-records/:trade_no/mark-paid": () => adminAPI.markPurchaseRecordPaid(request),
    "DELETE /api/admin/pending-records": () => adminAPI.deletePendingRecords(request),

    // 工单 API（管理员）
    "GET /api/admin/tickets": () => ticketAPI.listAdminTickets(request),
    "GET /api/admin/tickets/:id": () => ticketAPI.getAdminTicketDetail(request),
    "POST /api/admin/tickets/:id/replies": () => ticketAPI.replyTicketAsAdmin(request),
    "POST /api/admin/tickets/:id/status": () => ticketAPI.updateTicketStatus(request),
    "GET /api/admin/tickets/pending-count": () => ticketAPI.getAdminPendingCount(request),
  };

  // 处理路由
  const routeKey = `${method} ${path}`;
  const handler = routes[routeKey];

  if (handler) {
    return await handler();
  }

  // 动态路由处理
  for (const [route, handler] of Object.entries(routes)) {
    const [routeMethod, routePath] = route.split(" ");
    if (method === routeMethod && matchRoute(path, routePath)) {
      return await handler();
    }
  }

  // 如果没有匹配的路由，返回404
  return errorResponse("API endpoint not found", 404);
}

function matchRoute(path, pattern) {
  const pathParts = path.split("/").filter(Boolean);
  const patternParts = pattern.split("/").filter(Boolean);

  if (pathParts.length !== patternParts.length) return false;

  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i].startsWith(":")) continue;
    if (pathParts[i] !== patternParts[i]) return false;
  }

  return true;
}

// 健康检查
async function getHealthStatus(env) {
  try {
    const timestamp = new Date().toISOString();
    return successResponse({
      status: "healthy",
      message: "API服务正常运行",
      timestamp,
      version: env.APP_VERSION || "1.0.0",
      build_time: env.BUILD_TIME || new Date().toISOString()
    });
  } catch (error) {
    return errorResponse("Health check failed: " + error.message, 500);
  }
}

// 数据库连接测试
async function testDatabaseConnection(env) {
  try {
    const db = new DatabaseService(env.DB);
    const start = Date.now();

    await db.db.prepare("SELECT 1 as test").first();

    return successResponse({
      status: "connected",
      message: "数据库连接正常",
      latency_ms: Date.now() - start,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    return errorResponse("Database connection failed: " + error.message, 500);
  }
}

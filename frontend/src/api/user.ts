import http from "./http";
import type { 
  ApiResponse, 
  Node,
  NodesResponse,
  TrafficStats,
  TrafficRecord,
  PaginationResponse,
  PaginationParams
} from "./types";

/**
 * 获取可访问节点列表
 */
export const getUserNodes = (
  params?: PaginationParams & { type?: string; status?: string | number }
): Promise<ApiResponse<NodesResponse>> => {
  return http.get("/user/nodes", { params });
};

/**
 * 获取流量统计信息
 */
export const getTrafficStats = (days: number = 30): Promise<ApiResponse<TrafficStats>> => {
  return http.get(`/user/traffic-stats?days=${days}`);
};

// 定义流量趋势数据类型
interface TrafficTrendItem {
  date: string;
  label: string;
  upload_traffic: number;
  download_traffic: number;
  total_traffic: number;
}

/**
 * 获取流量趋势数据
 */
export const getTrafficTrends = (period: 'today' | '3days' | '7days' = 'today'): Promise<ApiResponse<TrafficTrendItem[]>> => {
  return http.get(`/user/traffic/trends?period=${period}`);
};

// 定义流量统计摘要类型
interface TrafficSummary {
  weekly: {
    week_upload: number;
    week_download: number;
    week_total: number;
    active_days: number;
  };
  monthly: {
    month_upload: number;
    month_download: number;
    month_total: number;
    active_days: number;
  };
  peak: {
    record_date: string;
    total_traffic: number;
    upload_traffic: number;
    download_traffic: number;
  } | null;
}

/**
 * 获取流量统计摘要
 */
export const getTrafficSummary = (): Promise<ApiResponse<TrafficSummary>> => {
  return http.get("/user/traffic/summary");
};

/**
 * 重置订阅令牌
 */
export const resetSubscriptionToken = (): Promise<ApiResponse<{ token: string }>> => {
  return http.post("/user/reset-subscription-token");
};

/**
 * 手动更新流量记录
 */
export const manualTrafficUpdate = (): Promise<ApiResponse<null>> => {
  return http.post("/user/traffic/manual-update");
};

/**
 * 更新用户资料
 */
export const updateUserProfile = (data: {
  email?: string;
  username?: string;
  telegram_id?: number;
}): Promise<ApiResponse<any>> => {
  return http.put("/user/profile", data);
};

/**
 * 修改用户密码
 */
export const changeUserPassword = (data: {
  current_password: string;
  new_password: string;
}): Promise<ApiResponse<null>> => {
  return http.post("/user/change-password", data);
};

/**
 * 获取用户流量详情记录
 */
export const getUserTrafficRecords = (
  params: PaginationParams & {
    start_date?: string;
    end_date?: string;
    start_time?: string;
    end_time?: string;
    node_id?: string;
  } = {}
): Promise<ApiResponse<PaginationResponse<TrafficRecord>>> => {
  return http.get("/user/traffic-records", { params });
};

/**
 * 获取订阅记录
 */
export const getSubscriptionLogs = (params?: {
  page?: number;
  limit?: number;
  type?: string;
}): Promise<ApiResponse<PaginationResponse<any>>> => {
  return http.get("/user/subscription-logs", { params });
};

/**
 * 获取Bark设置
 */
export const getBarkSettings = (): Promise<ApiResponse<{
  bark_key: string;
  bark_enabled: boolean;
}>> => {
  return http.get("/user/bark-settings");
};

/**
 * 更新Bark设置
 */
export const updateBarkSettings = (data: {
  bark_key: string;
  bark_enabled: boolean;
}): Promise<ApiResponse<{ message: string }>> => {
  return http.put("/user/bark-settings", data);
};

/**
 * 测试Bark通知
 */
export const testBarkNotification = (barkKey?: string): Promise<ApiResponse<{ message: string; success: boolean }>> => {
  return http.post("/user/bark-test", barkKey ? { bark_key: barkKey } : {});
};

/**
 * 获取登录记录
 */
export const getLoginLogs = (params?: {
  limit?: number;
}): Promise<ApiResponse<{
  data: Array<{
    id: number;
    login_ip: string;
    login_time: string;
    user_agent?: string;
    login_status: number;
    failure_reason?: string;
  }>;
}>> => {
  return http.get("/user/login-logs", { params });
};

export const getReferralOverview = (params?: {
  page?: number;
  limit?: number;
}): Promise<ApiResponse<any>> => {
  return http.get("/user/referrals", { params });
};

export const getRebateLedger = (params?: {
  page?: number;
  limit?: number;
  event_type?: string;
}): Promise<ApiResponse<any>> => {
  return http.get("/user/rebate/ledger", { params });
};

export const transferRebate = (data: {
  amount: number;
}): Promise<ApiResponse<{ money: number; rebateAvailable: number }>> => {
  return http.post("/user/rebate/transfer", data);
};

export const createRebateWithdrawal = (data: {
  amount: number;
  method?: string;
  accountPayload?: Record<string, unknown>;
}): Promise<ApiResponse<{ id: number }>> => {
  return http.post("/user/rebate/withdraw", data);
};

export const getUserRebateWithdrawals = (params?: {
  page?: number;
  limit?: number;
}): Promise<ApiResponse<any>> => {
  return http.get("/user/rebate/withdrawals", { params });
};
/**
 * 获取用户钱包信息
 */
export const getUserWalletInfo = (): Promise<ApiResponse<{
  balance: number;
  total_recharge: number;
  total_consume: number;
}>> => {
  return http.get("/user/wallet");
};

/**
 * 获取充值记录
 */
export const getUserRechargeRecords = (params?: {
  page?: number;
  limit?: number;
  status?: number | string;
}): Promise<ApiResponse<{
  records: Array<{
    id: number;
    trade_no: string;
    amount: number;
    status: number;
    pay_url?: string;
    created_at: string;
  }>;
  pagination: {
    total: number;
    page: number;
    limit: number;
  };
}>> => {
  return http.get("/user/recharge-records", { params });
};

export interface SharedIdItem {
  id: number;
  name: string;
  remote_account_id: number | number[];
  status: 'ok' | 'missing' | 'error';
  account: Record<string, unknown> | null;
  accounts?: Record<string, unknown>[];
  missing_ids?: number[];
  fetched_at?: string;
  message?: string | null;
  error?: string;
}

export const getUserSharedIds = (): Promise<ApiResponse<{ items: SharedIdItem[] }>> => {
  return http.get("/user/shared-ids");
};

/**
 * 创建充值订单
 */
export const createRechargeOrder = (data: {
  amount: number;
  paymentMethod: string;
}): Promise<ApiResponse<{
  trade_no: string;
  pay_url: string;
}>> => {
  return http.post("/user/recharge", data);
};

/**
 * 礼品卡兑换
 */
export const redeemGiftCard = (code: string): Promise<ApiResponse<{
  code: string;
  card_type: string;
  message?: string;
}>> => {
  return http.post("/wallet/gift-card/redeem", { code });
};

export const startTwoFactorSetup = (): Promise<ApiResponse<{
  secret: string;
  otp_auth_url: string;
  provisioning_uri: string;
}>> => {
  return http.post("/user/two-factor/setup");
};

export const enableTwoFactor = (data: { code: string }): Promise<ApiResponse<{
  message: string;
  backup_codes: string[];
}>> => {
  return http.post("/user/two-factor/enable", data);
};

export const regenerateTwoFactorBackupCodes = (data: { code: string }): Promise<ApiResponse<{
  message: string;
  backup_codes: string[];
}>> => {
  return http.post("/user/two-factor/backup-codes", data);
};

export const disableTwoFactor = (data: { password: string; code: string }): Promise<ApiResponse<{ message: string }>> => {
  return http.post("/user/two-factor/disable", data);
};

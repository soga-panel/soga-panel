import http, { httpClient } from "./http";
import type { ApiResponse, PaginationResponse, PaginationParams } from "./types";

// 公告接口类型定义
export interface Announcement {
  id: number;
  title: string;
  content: string;
  type: 'notice' | 'warning' | 'important' | 'maintenance';
  status: number;
  is_pinned: boolean;
  priority: number;
  created_at: string;
  updated_at: string;
}

export interface CreateAnnouncementRequest {
  title: string;
  content: string;
  type: string;
  status: number;
  is_pinned?: boolean;
  priority?: number;
}

export interface UpdateAnnouncementRequest extends CreateAnnouncementRequest {
  id: number;
}

// 公告管理API
export const getAnnouncements = (params?: PaginationParams): Promise<ApiResponse<PaginationResponse<Announcement>>> => {
  return http.get("/admin/announcements", { params });
};

export const createAnnouncement = (data: CreateAnnouncementRequest): Promise<ApiResponse<Announcement>> => {
  return http.post("/admin/announcements", data);
};

export const updateAnnouncement = (id: number, data: CreateAnnouncementRequest): Promise<ApiResponse<Announcement>> => {
  return http.put(`/admin/announcements/${id}`, data);
};

export const deleteAnnouncement = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/announcements/${id}`);
};

// 用户管理API
export interface User {
  id: number;
  email: string;
  username: string;
  uuid: string;
  class: number;
  status: number;
  transfer_enable: number;
  transfer_total: number;
  expire_time: string | null;
  created_at: string;
  updated_at: string;
  class_expire_time?: string | null;
  speed_limit?: number;
  device_limit?: number;
  bark_key?: string;
  bark_enabled?: boolean;
  is_admin?: number;
  money?: number | string;
  register_ip?: string | null;
  invite_code?: string | null;
  invite_limit?: number | null;
  invite_used?: number | null;
}

export interface CreateUserRequest {
  email: string;
  username: string;
  password: string;
  class?: number;
  transfer_enable?: number;
  expire_days?: number;
  expire_time?: string;
  class_expire_time?: string;
  speed_limit?: number;
  device_limit?: number;
  bark_key?: string;
  bark_enabled?: boolean;
  invite_code?: string;
  invite_limit?: number;
}

export interface UpdateUserRequest {
  email?: string;
  username?: string;
  class?: number;
  status?: number;
  transfer_enable?: number;
  expire_time?: string;
  class_expire_time?: string;
  speed_limit?: number;
  device_limit?: number;
  bark_key?: string;
  bark_enabled?: boolean;
  money?: number;
  invite_code?: string;
  invite_limit?: number;
}

export interface UserListResponse {
  users: User[];
  total: number;
  pagination?: {
    total: number;
    page: number;
    limit: number;
    pages?: number;
  };
}

export const getUsers = (params?: PaginationParams & {
  status?: number;
  class?: number;
  search?: string;
}): Promise<ApiResponse<UserListResponse>> => {
  return http.get("/admin/users", { params });
};

export const createUser = (data: CreateUserRequest): Promise<ApiResponse<User>> => {
  return http.post("/admin/users", data);
};

export const updateUser = (id: number, data: UpdateUserRequest): Promise<ApiResponse<User>> => {
  return http.put(`/admin/users/${id}`, data);
};

export const deleteUser = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/users/${id}`);
};

export const toggleUserStatus = (id: number): Promise<ApiResponse<null>> => {
  return http.post(`/admin/users/${id}/status`);
};

export const resetUserTraffic = (id: number): Promise<ApiResponse<null>> => {
  return http.post(`/admin/users/${id}/traffic`);
};

export const exportUsersCSV = (userIds?: number[]): Promise<string> => {
  return httpClient
    .get<string>("/admin/users/export", {
      responseType: "text",
      params: { ids: userIds }
    })
    .then((response) => response.data);
};

// 优惠券管理API
export interface Coupon {
  id: number;
  name: string;
  code: string;
  discount_type: "amount" | "percentage";
  discount_value: number;
  start_at: number;
  end_at: number;
  max_usage?: number | null;
  per_user_limit?: number | null;
  total_used?: number;
  remaining_usage?: number | null;
  status: number;
  description?: string | null;
  package_count?: number;
}

export interface CouponPayload {
  name: string;
  code?: string;
  discount_type: "amount" | "percentage";
  discount_value: number;
  start_at: number;
  end_at: number;
  max_usage?: number | null;
  per_user_limit?: number | null;
  package_ids?: number[];
  status?: number;
  description?: string;
}

export const getCoupons = (params?: {
  page?: number;
  limit?: number;
  status?: number | string;
  keyword?: string;
}): Promise<ApiResponse<{
  coupons: Coupon[];
  pagination: PaginationParams & { total: number; totalPages: number };
}>> => {
  return http.get("/admin/coupons", { params });
};

export const getCouponDetail = (id: number): Promise<ApiResponse<Coupon & { package_ids: number[] }>> => {
  return http.get(`/admin/coupons/${id}`);
};

export const createCoupon = (data: CouponPayload): Promise<ApiResponse<Coupon>> => {
  return http.post("/admin/coupons", data);
};

export const updateCoupon = (id: number, data: Partial<CouponPayload>): Promise<ApiResponse<{ id: number }>> => {
  return http.put(`/admin/coupons/${id}`, data);
};

export const deleteCoupon = (id: number): Promise<ApiResponse<{ id: number }>> => {
  return http.delete(`/admin/coupons/${id}`);
};

// 礼品卡管理API
export interface GiftCard {
  id: number;
  name: string;
  code: string;
  card_type: string;
  status: number;
  balance_amount?: number | null;
  duration_days?: number | null;
  traffic_value_gb?: number | null;
  reset_traffic_gb?: number | null;
  package_id?: number | null;
  package_name?: string | null;
  max_usage?: number | null;
  per_user_limit?: number | null;
  used_count?: number | null;
  remaining_usage?: number | null;
  start_at?: string | null;
  end_at?: string | null;
  created_at?: string | null;
  batch_name?: string | null;
  is_expired?: boolean;
}

export interface GiftCardPayload {
  name: string;
  card_type: string;
  code?: string;
  balance_amount?: number | null;
  duration_days?: number | null;
  traffic_value_gb?: number | null;
  reset_traffic_gb?: number | null;
  package_id?: number | null;
  start_at?: string | Date | null;
  end_at?: string | Date | null;
  max_usage?: number | null;
  per_user_limit?: number | null;
  quantity?: number | null;
}

export interface GiftCardRedemption {
  id: number;
  user_id: number;
  user_email?: string | null;
  user_name?: string | null;
  code: string;
  card_type: string;
  change_amount?: number | null;
  duration_days?: number | null;
  traffic_value_gb?: number | null;
  reset_traffic_gb?: number | null;
  package_id?: number | null;
  trade_no?: string | null;
  message?: string | null;
  created_at?: string | null;
}

export const getGiftCards = (params?: {
  page?: number;
  limit?: number;
  status?: number | string;
  card_type?: string;
  keyword?: string;
}): Promise<ApiResponse<{
  records: GiftCard[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}>> => {
  return http.get('/admin/gift-cards', { params });
};

export const createGiftCard = (data: GiftCardPayload): Promise<ApiResponse<{ batch_id: number; cards: GiftCard[] }>> => {
  return http.post('/admin/gift-cards', data);
};

export const updateGiftCard = (id: number, data: Partial<GiftCardPayload>): Promise<ApiResponse<{ id: number }>> => {
  return http.put(`/admin/gift-cards/${id}`, data);
};

export const updateGiftCardStatus = (id: number, status: number): Promise<ApiResponse<{ id: number; status: number }>> => {
  return http.post(`/admin/gift-cards/${id}/status`, { status });
};

export const deleteGiftCard = (id: number): Promise<ApiResponse<{ id: number }>> => {
  return http.delete(`/admin/gift-cards/${id}`);
};

export const getGiftCardRedemptions = (id: number, params?: {
  page?: number;
  limit?: number;
}): Promise<ApiResponse<{
  records: GiftCardRedemption[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}>> => {
  return http.get(`/admin/gift-cards/${id}/redemptions`, { params });
};

// 节点管理API
export interface Node {
  id: number;
  name: string;
  type: string;
  server: string;
  server_port: number;
  tls_host?: string;
  node_class: number;
  node_bandwidth: number;
  node_bandwidth_limit: number;
  traffic_multiplier?: number;
  bandwidthlimit_resetday?: number;
  node_config: string;
  status: number;
  user_count?: number;
  is_online?: boolean;
  created_at: string;
  updated_at: string;
}

export interface NodeStatus {
  id: number;
  name: string;
  type: string;
  server: string;
  server_port: number;
  tls_host?: string;
  node_class: number;
  status: number;
  cpu_usage?: number;
  memory_total?: number;
  memory_used?: number;
  swap_total?: number;
  swap_used?: number;
  disk_total?: number;
  disk_used?: number;
  uptime?: number;
  last_reported?: string;
  is_online?: boolean;
}

export interface NodeStatusStatistics {
  total: number;
  online: number;
  offline: number;
  enabled?: number;
  disabled?: number;
}

export interface NodeStatusResponse {
  nodes: NodeStatus[];
  statistics: NodeStatusStatistics;
  pagination?: {
    total: number;
    page: number;
    limit: number;
  };
}

export interface CreateNodeRequest {
  name: string;
  type: string;
  server: string;
  server_port: number;
  tls_host?: string;
  node_class: number;
  node_bandwidth_limit?: number;
  traffic_multiplier?: number;
  node_config?: string;
  bandwidthlimit_resetday?: number;
}

export const getNodes = (params?: PaginationParams): Promise<ApiResponse<PaginationResponse<Node>>> => {
  return http.get("/admin/nodes", { params });
};

export const getNodeStatusList = (params?: PaginationParams & {
  keyword?: string;
  status?: string | number;
  online?: string | number;
}): Promise<ApiResponse<NodeStatusResponse>> => {
  return http.get("/admin/node-status", { params });
};

export const createNode = (data: CreateNodeRequest): Promise<ApiResponse<Node>> => {
  return http.post("/admin/nodes", data);
};

export const updateNode = (id: number, data: Partial<CreateNodeRequest>): Promise<ApiResponse<Node>> => {
  return http.put(`/admin/nodes/${id}`, data);
};

export const deleteNode = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/nodes/${id}`);
};

export const batchUpdateNodes = (data: {
  action: 'enable' | 'disable' | 'delete';
  node_ids: number[];
}): Promise<ApiResponse<{
  message: string;
  affected_count: number;
  processed_ids: number[];
}>> => {
  return http.post('/admin/nodes/batch', data);
};

export interface SharedIdConfig {
  id: number;
  name: string;
  fetch_url: string;
  remote_account_id: number | number[];
  status: number;
  created_at?: string;
  updated_at?: string;
}

export const getSharedIdConfigs = (params?: {
  page?: number;
  limit?: number;
  keyword?: string;
  status?: string | number;
}): Promise<ApiResponse<{
  records: SharedIdConfig[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}>> => {
  return http.get("/admin/shared-ids", { params });
};

export const createSharedIdConfig = (data: {
  name: string;
  fetch_url: string;
  remote_account_id: number | number[];
  status?: number;
}): Promise<ApiResponse<{ record: SharedIdConfig }>> => {
  return http.post("/admin/shared-ids", data);
};

export const updateSharedIdConfig = (
  id: number,
  data: {
    name?: string;
    fetch_url?: string;
    remote_account_id?: number | number[];
    status?: number;
  }
): Promise<ApiResponse<{ record: SharedIdConfig }>> => {
  return http.put(`/admin/shared-ids/${id}`, data);
};

export const deleteSharedIdConfig = (id: number): Promise<ApiResponse<{ id: number }>> => {
  return http.delete(`/admin/shared-ids/${id}`);
};

// 系统统计API
export interface SystemStats {
  users: {
    total: number;
    active: number;
    disabled: number;
    admins: number;
  };
  nodes: {
    total: number;
    active: number;
    online: number;
    offline: number;
  };
  traffic: {
    total: number;
    today: number;
    average_quota: number;
  };
}

export const getSystemStats = (): Promise<ApiResponse<SystemStats>> => {
  return http.get("/admin/system-stats");
};

// 登录记录API
export interface LoginLog {
  id: number;
  user_id: number;
  user_email?: string;
  login_ip: string;
  login_time: string;
  user_agent?: string;
  login_status: number;
  failure_reason?: string;
  login_method?: string;
  created_at: string;
}

export const getLoginLogs = (params?: PaginationParams & {
  user_id?: number;
  status?: number;
  ip?: string;
}): Promise<ApiResponse<PaginationResponse<LoginLog>>> => {
  return http.get("/admin/login-logs", { params });
};

export const deleteLoginLog = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/login-logs/${id}`);
};

export const batchDeleteLoginLogs = (ids: number[]): Promise<ApiResponse<null>> => {
  return http.post("/admin/login-logs/batch-delete", { ids });
};

export const exportLoginLogsCSV = (ids?: number[]): Promise<string> => {
  return httpClient
    .post<string>("/admin/login-logs/export-csv", { ids }, { responseType: "text" })
    .then((response) => response.data);
};

// 订阅记录API
export interface SubscriptionLog {
  id: number;
  user_id: number;
  user_email: string;
  type: string;
  request_ip: string;
  request_time: string;
  request_user_agent: string;
}

export const getSubscriptionLogs = (params?: PaginationParams & {
  user_id?: number;
  type?: string;
}): Promise<ApiResponse<PaginationResponse<SubscriptionLog>>> => {
  return http.get("/admin/subscription-logs", { params });
};

export const deleteSubscriptionLog = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/subscription-logs/${id}`);
};

export const batchDeleteSubscriptionLogs = (ids: number[]): Promise<ApiResponse<null>> => {
  return http.post("/admin/subscription-logs/batch-delete", { ids });
};

export const exportSubscriptionLogsCSV = (ids?: number[]): Promise<string> => {
  return httpClient
    .post<string>("/admin/subscription-logs/export-csv", { ids }, { responseType: "text" })
    .then((response) => response.data);
};

// 在线IP管理API
export interface OnlineIP {
  id: number;
  user_id: number;
  user_email: string;
  user_class: number;
  ip_address: string;
  node_id: number;
  node_name: string;
  node_type: string;
  protocol?: string;
  connect_time: string;
  last_active?: string;
  upload_traffic?: number;
  download_traffic?: number;
  upload_speed?: number;
  download_speed?: number;
}

export const getOnlineIPs = (params?: PaginationParams & {
  node_id?: number;
  user_email?: string;
  ip?: string;
  sort_by?: string;
}): Promise<ApiResponse<PaginationResponse<OnlineIP>>> => {
  return http.get("/admin/online-ips", { params });
};

export const kickIP = (id: number): Promise<ApiResponse<null>> => {
  return http.post(`/admin/online-ips/${id}/kick`);
};

export const deleteOnlineIP = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/online-ips/${id}`);
};

export const batchDeleteOnlineIPs = (ids: number[]): Promise<ApiResponse<null>> => {
  return http.post("/admin/online-ips/batch-delete", { ids });
};

export const exportOnlineIPsCSV = (ids?: number[]): Promise<string> => {
  return httpClient
    .post<string>("/admin/online-ips/export-csv", { ids }, { responseType: "text" })
    .then((response) => response.data);
};

export const blockIP = (ip: string): Promise<ApiResponse<null>> => {
  return http.post(`/admin/block-ip`, { ip });
};

// 审计规则管理API
export interface AuditRule {
  id: number;
  name: string;
  rule: string;
  description?: string;
  enabled: number;
  created_at: string;
  updated_at: string;
}

export interface CreateAuditRuleRequest {
  name: string;
  rule: string;
  description?: string;
  enabled: number;
}

export const getAuditRules = (params?: PaginationParams & {
  enabled?: number;
  search?: string;
}): Promise<ApiResponse<PaginationResponse<AuditRule>>> => {
  return http.get("/admin/audit-rules", { params });
};

export const createAuditRule = (data: CreateAuditRuleRequest): Promise<ApiResponse<AuditRule>> => {
  return http.post("/admin/audit-rules", data);
};

export const updateAuditRule = (id: number, data: Partial<CreateAuditRuleRequest>): Promise<ApiResponse<AuditRule>> => {
  return http.put(`/admin/audit-rules/${id}`, data);
};

export const deleteAuditRule = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/audit-rules/${id}`);
};

export const testAuditRule = (id: number, content: string): Promise<ApiResponse<{
  matched: boolean;
  rule_name: string;
  matched_content?: string;
}>> => {
  return http.post(`/admin/audit-rules/${id}/test`, { content });
};

// 审计记录管理API
export interface AuditLog {
  id: number;
  user_id?: number;
  user_email?: string;
  rule_id: number;
  rule_name: string;
  rule_type: string;
  action: string;
  target_ip?: string;
  target_domain?: string;
  target_port?: number;
  protocol?: string;
  matched_content?: string;
  severity: string;
  additional_info?: string;
  created_at: string;
}

export const getAuditLogs = (params?: PaginationParams & {
  action?: string;
  rule_id?: string;
  user_email?: string;
  target_ip?: string;
}): Promise<ApiResponse<PaginationResponse<AuditLog>>> => {
  return http.get("/admin/audit-logs", { params });
};

export const deleteAuditLog = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/audit-logs/${id}`);
};

export const batchDeleteAuditLogs = (ids: number[]): Promise<ApiResponse<null>> => {
  return http.post("/admin/audit-logs/batch-delete", { ids });
};

// 白名单管理API
export interface WhitelistRule {
  id: number;
  rule: string;
  description?: string;
  status: number;
  created_at: string;
}

export interface CreateWhitelistRuleRequest {
  rule: string;
  description?: string;
  status: number;
}

export const getWhitelistRules = (params?: PaginationParams & {
  status?: number;
  search?: string;
}): Promise<ApiResponse<PaginationResponse<WhitelistRule>>> => {
  return http.get("/admin/whitelist", { params });
};

export const createWhitelistRule = (data: CreateWhitelistRuleRequest): Promise<ApiResponse<WhitelistRule>> => {
  return http.post("/admin/whitelist", data);
};

export const updateWhitelistRule = (id: number, data: Partial<CreateWhitelistRuleRequest>): Promise<ApiResponse<WhitelistRule>> => {
  return http.put(`/admin/whitelist/${id}`, data);
};

export const deleteWhitelistRule = (id: number): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/whitelist/${id}`);
};

export const batchWhitelistOperation = (action: 'enable' | 'disable' | 'delete', ids: number[]): Promise<ApiResponse<{
  message: string;
  affected_count: number;
}>> => {
  return http.post("/admin/whitelist/batch", { action, ids });
};

// 管理员操作接口
export const resetDailyTraffic = (): Promise<ApiResponse<{
  message: string;
  count: number;
}>> => {
  return http.post("/admin/reset-daily-traffic");
};

export const resetAllUserPasswords = (): Promise<ApiResponse<{
  message: string;
  count: number;
}>> => {
  return http.post("/admin/reset-all-passwords");
};

export const resetAllSubscriptionTokens = (): Promise<ApiResponse<{
  message: string;
  count: number;
}>> => {
  return http.post("/admin/reset-all-subscriptions");
};

export const triggerTrafficReset = (): Promise<ApiResponse<{
  message: string;
  success: boolean;
  processed_users?: number;
  reset_count?: number;
}>> => {
  return http.post("/admin/trigger-traffic-reset");
};

// 缓存管理接口
export interface CacheStatus {
  total_keys: number;
  categories: {
    node_config: number;
    node_users: number;
    audit_rules: number;
    white_list: number;
    others: number;
  };
  cache_keys: string[];
}

export interface ClearCacheResponse {
  message: string;
  cleared_at: string;
  cleared_types?: string[];
}

export const getCacheStatus = (): Promise<ApiResponse<{
  cache_status: CacheStatus;
  timestamp: string;
}>> => {
  return http.get("/admin/cache-status");
};

export const clearAllCache = (): Promise<ApiResponse<ClearCacheResponse>> => {
  return http.post("/admin/clear-cache/all");
};

export const clearNodeCache = (): Promise<ApiResponse<ClearCacheResponse>> => {
  return http.post("/admin/clear-cache/nodes");
};

export const clearAuditRulesCache = (): Promise<ApiResponse<ClearCacheResponse>> => {
  return http.post("/admin/clear-cache/audit-rules");
};

export const clearWhitelistCache = (): Promise<ApiResponse<ClearCacheResponse>> => {
  return http.post("/admin/clear-cache/whitelist");
};

// 系统配置管理API
export interface SystemConfig {
  id: number;
  key: string;
  value: string;
  description: string;
}

export interface SystemConfigUpdate {
  key: string;
  value: string;
}

export interface SystemConfigBatchUpdate {
  configs: SystemConfigUpdate[];
}

export const getSystemConfigs = (): Promise<ApiResponse<SystemConfig[]>> => {
  return http.get("/admin/system-configs");
};

export const updateSystemConfig = (data: SystemConfigUpdate): Promise<ApiResponse<null>> => {
  return http.put("/admin/system-configs", data);
};

export const updateSystemConfigsBatch = (data: SystemConfigBatchUpdate): Promise<ApiResponse<null>> => {
  return http.put("/admin/system-configs/batch", data);
};

export const addSystemConfig = (data: SystemConfig): Promise<ApiResponse<null>> => {
  return http.post("/admin/system-configs", data);
};

export const deleteSystemConfig = (key: string): Promise<ApiResponse<null>> => {
  return http.delete(`/admin/system-configs/${key}`);
};

export const getRebateWithdrawals = (params?: {
  page?: number;
  limit?: number;
  status?: string;
}): Promise<ApiResponse<any>> => {
  return http.get("/admin/rebate/withdrawals", { params });
};

export const reviewRebateWithdrawal = (data: {
  id: number;
  status: "approved" | "rejected" | "paid";
  note?: string;
}): Promise<ApiResponse<any>> => {
  return http.post("/admin/rebate/withdrawals/review", data);
};

export const resetAllInviteCodes = (): Promise<ApiResponse<{ count: number; message?: string }>> => {
  return http.post("/admin/invite-codes/reset");
};

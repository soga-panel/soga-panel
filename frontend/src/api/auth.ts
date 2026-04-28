import http from "./http";
import type {
  ApiResponse,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  SendEmailCodeResponse,
  PasswordResetRequestPayload,
  PasswordResetConfirmPayload,
  GoogleLoginRequest,
  GithubLoginRequest,
  User,
} from "./types";

/**
 * 用户登录
 */
export const login = (data: LoginRequest): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/login", data);
};

/**
 * Telegram Mini App 登录
 */
export const loginWithTelegramMiniApp = (data: {
  initData: string;
  remember?: boolean;
  twoFactorTrustToken?: string;
}): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/telegram-miniapp", data);
};

/**
 * Google OAuth 登录
 */
export const loginWithGoogle = (
  data: GoogleLoginRequest
): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/google", data);
};

/**
 * GitHub OAuth 登录
 */
export const loginWithGithub = (
  data: GithubLoginRequest
): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/github", data);
};

export const completePendingOAuthRegistration = (data: {
  pendingToken: string;
  inviteCode?: string;
}): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/oauth/complete", data);
};

/**
 * 用户注册
 */
export const register = (data: RegisterRequest): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/register", data);
};

/**
 * 发送注册邮箱验证码
 */
export const sendRegisterEmailCode = (data: { email: string }): Promise<ApiResponse<SendEmailCodeResponse>> => {
  return http.post("/auth/send-email-code", data);
};

/**
 * 发送密码重置验证码
 */
export const sendPasswordResetCode = (data: PasswordResetRequestPayload): Promise<ApiResponse<SendEmailCodeResponse>> => {
  return http.post("/auth/password-reset/request", data);
};

/**
 * 确认密码重置
 */
export const confirmPasswordReset = (data: PasswordResetConfirmPayload): Promise<ApiResponse<null>> => {
  return http.post("/auth/password-reset/confirm", data);
};

/**
 * 获取注册配置
 */
export const getRegisterConfig = (): Promise<ApiResponse<{
  registerEnabled: boolean;
  registerMode: string;
  inviteRequired: boolean;
  verificationEnabled: boolean;
  passwordResetEnabled: boolean;
  emailProviderEnabled: boolean;
}>> => {
  return http.get("/auth/register-config");
};

/**
 * 用户登出
 */
export const logout = (): Promise<ApiResponse<null>> => {
  return http.post("/auth/logout");
};

/**
 * 获取用户个人信息
 */
export const getUserProfile = (): Promise<ApiResponse<User>> => {
  return http.get("/user/profile");
};

/**
 * 更新个人信息
 */
export const updateProfile = (data: {
  username?: string;
  email?: string;
}): Promise<ApiResponse<null>> => {
  return http.put("/user/profile", data);
};

/**
 * 修改密码
 */
export const changePassword = (data: {
  current_password: string;
  new_password: string;
}): Promise<ApiResponse<null>> => {
  return http.post("/user/change-password", data);
};

/**
 * 二步验证校验
 */
export const verifyTwoFactor = (data: {
  challenge_id: string;
  code: string;
  rememberDevice?: boolean;
  deviceName?: string;
}): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/verify-2fa", data);
};

export const getPasskeyLoginOptions = (data: {
  email: string;
  remember?: boolean;
}): Promise<ApiResponse<any>> => {
  return http.post("/auth/passkey/login/options", data);
};

export const verifyPasskeyLogin = (data: {
  credential: any;
}): Promise<ApiResponse<LoginResponse>> => {
  return http.post("/auth/passkey/login/verify", data);
};

export const getPasskeyRegisterOptions = (): Promise<ApiResponse<any>> => {
  return http.post("/auth/passkey/register/options");
};

export const verifyPasskeyRegister = (data: {
  credential: any;
  deviceName?: string;
}): Promise<ApiResponse<any>> => {
  return http.post("/auth/passkey/register/verify", data);
};

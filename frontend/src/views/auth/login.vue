<template>
  <div class="login-page">
    <div class="login-panel">
      <div class="brand">
        <div class="brand-logo">S</div>
        <div class="brand-title">{{ appTitle }}</div>
      </div>

      <el-form
        ref="loginFormRef"
        :model="loginForm"
        :rules="loginRules"
        class="login-form"
        @keyup.enter="handleLogin"
      >
        <el-form-item prop="email">
          <el-input
            v-model="loginForm.email"
            placeholder="请输入邮箱地址"
            size="large"
            clearable
            :prefix-icon="User"
          />
        </el-form-item>
        <el-form-item prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="请输入密码"
            size="large"
            show-password
            clearable
            :prefix-icon="Lock"
          />
        </el-form-item>
      </el-form>

      <div class="form-options">
        <el-checkbox v-model="rememberLogin">7天内免登录</el-checkbox>
        <el-button
          v-if="forgotPasswordVisible"
          type="primary"
          link
          @click="goToForgotPassword"
        >
          忘记密码？
        </el-button>
      </div>

      <div v-if="turnstileEnabled" class="turnstile-container">
        <div ref="turnstileEl" class="cf-turnstile-placeholder"></div>
      </div>

      <el-button
        type="primary"
        size="large"
        class="submit-btn"
        :loading="loading"
        @click="handleLogin"
      >
        登录
      </el-button>

      <div class="third-party">
        <div class="third-title">
          <span>其他登录</span>
        </div>
        <div class="third-icons">
          <div
            class="third-icon github"
            @click="handleGithubClick"
          >
            <span class="icon-wrapper">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                viewBox="0 0 512 512"
                aria-label="GitHub logo"
              >
                <path
                  fill="currentColor"
                  d="M256 32C132.3 32 32 134.9 32 261.7c0 101.5 64.2 187.5 153.2 217.9a17.56 17.56 0 0 0 3.8.4c8.3 0 11.5-6.1 11.5-11.4c0-5.5-.2-19.9-.3-39.1a102.4 102.4 0 0 1-22.6 2.7c-43.1 0-52.9-33.5-52.9-33.5c-10.2-26.5-24.9-33.6-24.9-33.6c-19.5-13.7-.1-14.1 1.4-14.1h.1c22.5 2 34.3 23.8 34.3 23.8c11.2 19.6 26.2 25.1 39.6 25.1a63 63 0 0 0 25.6-6c2-14.8 7.8-24.9 14.2-30.7c-49.7-5.8-102-25.5-102-113.5c0-25.1 8.7-45.6 23-61.6c-2.3-5.8-10-29.2 2.2-60.8a18.64 18.64 0 0 1 5-.5c8.1 0 26.4 3.1 56.6 24.1a208.21 208.21 0 0 1 112.2 0c30.2-21 48.5-24.1 56.6-24.1a18.64 18.64 0 0 1 5 .5c12.2 31.6 4.5 55 2.2 60.8c14.3 16.1 23 36.6 23 61.6c0 88.2-52.4 107.6-102.3 113.3c8 7.1 15.2 21.1 15.2 42.5c0 30.7-.3 55.5-.3 63c0 5.4 3.1 11.5 11.4 11.5a19.35 19.35 0 0 0 4-.4C415.9 449.2 480 363.1 480 261.7C480 134.9 379.7 32 256 32"
                />
              </svg>
            </span>
            <div v-if="githubLoading" class="oauth-loading">
              <el-icon><Loading /></el-icon>
            </div>
          </div>
          <div
            class="third-icon google"
            @click="handleGoogleClick"
          >
            <span class="icon-wrapper">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 48 48"
                aria-label="Google logo"
                width="24"
                height="24"
              >
                <path
                  fill="#FFC107"
                  d="M43.611 20.083h-1.964v-.1H24v8h11.303C33.95 31.91 29.463 35 24 35c-6.627 0-12-5.373-12-12s5.373-12 12-12c3.058 0 5.84 1.154 7.961 3.039l5.657-5.657C34.756 5.053 29.658 3 24 3 12.955 3 4 11.955 4 23s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.651-.389-3.917z"
                />
                <path
                  fill="#FF3D00"
                  d="M6.306 14.691l6.571 4.817C14.127 16.156 18.684 13 24 13c3.058 0 5.84 1.154 7.961 3.039l5.657-5.657C34.756 5.053 29.658 3 24 3 16.318 3 9.679 7.337 6.306 14.691z"
                />
                <path
                  fill="#4CAF50"
                  d="M24 43c5.353 0 10.191-2.048 13.86-5.383l-6.39-5.405C29.462 33.91 25.79 35 24 35c-5.435 0-9.908-3.605-11.544-8.502l-6.55 5.046C8.253 38.556 15.601 43 24 43z"
                />
                <path
                  fill="#1976D2"
                  d="M43.611 20.083h-1.964v-.1H24v8h11.303c-1.026 2.963-3.186 5.246-6.133 6.612l6.39 5.405C38.834 37.152 44 32.5 44 23c0-1.341-.138-2.651-.389-3.917z"
                />
              </svg>
            </span>
            <GoogleLogin
              v-if="googleLoginEnabled"
              class="google-trigger"
              :callback="handleGoogleCredential"
              :buttonConfig="googleButtonConfig"
            />
            <div v-if="googleLoginEnabled && googleLoading" class="oauth-loading">
              <el-icon><Loading /></el-icon>
            </div>
          </div>
          <div
            class="third-icon passkey"
            :class="{ disabled: !passkeySupported }"
            @click="passkeySupported ? handlePasskeyLogin() : null"
          >
            <span class="icon-wrapper">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                aria-label="Passkey"
                fill="none"
              >
                <path
                  fill="#000000"
                  stroke-width="0.5"
                  d="M3 20v-2.35c0-.63335.158335-1.175.475-1.625.316665-.45.725-.79165 1.225-1.025 1.11665-.5 2.1875-.875 3.2125-1.125S9.96665 13.5 11 13.5c.43335 0 .85415.02085 1.2625.0625s.82915.10415 1.2625.1875c-.08335.96665.09585 1.87915.5375 2.7375C14.50415 17.34585 15.15 18.01665 16 18.5v1.5H3Zm16 3.675-1.5-1.5v-4.65c-.73335-.21665-1.33335-.62915-1.8-1.2375-.46665-.60835-.7-1.3125-.7-2.1125 0-.96665.34165-1.79165 1.025-2.475.68335-.68335 1.50835-1.025 2.475-1.025s1.79165.34165 2.475 1.025c.68335.68335 1.025 1.50835 1.025 2.475 0 .75-.2125 1.41665-.6375 2-.425.58335-.9625 1-1.6125 1.25l1.25 1.25-1.5 1.5 1.5 1.5-2 2ZM11 11.5c-1.05 0-1.9375-.3625-2.6625-1.0875-.725-.725-1.0875-1.6125-1.0875-2.6625s.3625-1.9375 1.0875-2.6625C9.0625 4.3625 9.95 4 11 4s1.9375.3625 2.6625 1.0875c.725.725 1.0875 1.6125 1.0875 2.6625s-.3625 1.9375-1.0875 2.6625C12.9375 11.1375 12.05 11.5 11 11.5Zm7.5 3.175c.28335 0 .52085-.09585.7125-.2875s.2875-.42915.2875-.7125c0-.28335-.09585-.52085-.2875-.7125s-.42915-.2875-.7125-.2875c-.28335 0-.52085.09585-.7125.2875s-.2875.42915-.2875.7125c0 .28335.09585.52085.2875.7125s.42915.2875.7125.2875Z"
                />
              </svg>
            </span>
          </div>
        </div>
      </div>

      <div class="register-tip">
        <span>还没有账号？</span>
        <el-button type="primary" link @click="goToRegister">
          立即注册
        </el-button>
      </div>
    </div>
  </div>

  <el-dialog
    v-model="showPasswordDialog"
    :title="welcomeTitle"
    width="420px"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    @close="handlePasswordDialogClose"
  >
    <p class="password-dialog-text">
      以下为通过 {{ lastOAuthProviderLabel }} 首次登录自动生成的密码，请妥善保管并尽快前往个人中心修改：
    </p>
    <el-input v-model="generatedPassword" readonly class="password-display">
      <template #suffix>
        <el-button text @click="copyGeneratedPassword">
          <el-icon><DocumentCopy /></el-icon>
        </el-button>
      </template>
    </el-input>
    <p class="password-dialog-tip">
      {{ passwordEmailSent ? "密码也已发送至您的邮箱，请注意查收。" : "当前未发送邮件，请务必自行保存该密码。" }}
    </p>
    <template #footer>
      <el-button type="primary" @click="handlePasswordDialogClose">
        知道了
      </el-button>
    </template>
  </el-dialog>

  <el-dialog
    v-model="twoFactorDialogVisible"
    :title="`${pendingTwoFactorProvider} 二步验证`"
    width="400px"
    :close-on-click-modal="false"
    :close-on-press-escape="false"
    @close="closeTwoFactorDialog"
  >
    <p class="twofactor-tip">
      为了保护您的账号，请输入来自 {{ pendingTwoFactorProvider }} 的 6 位验证码或备用码。
    </p>
    <el-form class="twofactor-form">
      <el-form-item label="验证码">
        <el-input
          v-model="twoFactorForm.code"
          maxlength="16"
          placeholder="请输入验证码"
          autofocus
        />
      </el-form-item>
      <el-checkbox v-model="twoFactorForm.rememberDevice">
        记住此设备 30 天
      </el-checkbox>
    </el-form>
    <template #footer>
      <el-button @click="closeTwoFactorDialog">取消</el-button>
      <el-button type="primary" :loading="twoFactorSubmitting" @click="submitTwoFactor">
        验证
      </el-button>
    </template>
  </el-dialog>

  <TermsAgreement
    ref="oauthTermsRef"
    hide-checkbox
    decline-message="不同意将无法注册账号"
    @accepted="handleOAuthTermsAccepted"
    @declined="handleOAuthTermsDeclined"
  >
    <template #dialog-top>
      <div v-if="pendingOAuthToken" class="oauth-invite-block">
        <p class="oauth-invite-label">
          邀请码
          <span v-if="inviteRequiredForOAuth" class="required-indicator">*</span>
        </p>
        <el-input
          v-model="oauthInviteCode"
          size="large"
          placeholder="请输入邀请人提供的邀请码"
          clearable
        />
        <p class="oauth-invite-tip">
          若有邀请人请填写其分享的邀请码。
          <span v-if="inviteRequiredForOAuth">当前仅允许受邀注册。</span>
        </p>
        <p v-if="oauthInviteError" class="oauth-invite-error">{{ oauthInviteError }}</p>
      </div>
    </template>
  </TermsAgreement>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from "vue";
import { useRouter, useRoute } from "vue-router";
import {
  ElMessage,
  type FormInstance,
  type FormRules
} from "element-plus";
import {
  User,
  Lock,
  Loading,
  DocumentCopy
} from "@element-plus/icons-vue";
import { GoogleLogin } from "vue3-google-login";
import {
  login,
  loginWithTelegramMiniApp,
  loginWithGoogle,
  loginWithGithub,
  getRegisterConfig,
  verifyTwoFactor,
  completePendingOAuthRegistration,
  getPasskeyLoginOptions,
  verifyPasskeyLogin
} from "@/api/auth";
import { setToken } from "@/utils/auth-soga";
import { useUserStore } from "@/store/user";
import { useSiteStore } from "@/store/site";
import type { LoginRequest, LoginResponse } from "@/api/types";
import TermsAgreement from "@/components/auth/TermsAgreement.vue";
import {
  isPasskeySupported,
  performPasskeyLogin
} from "@/utils/passkey";

const router = useRouter();
const route = useRoute();
const userStore = useUserStore();
const loginFormRef = ref<FormInstance>();

const siteStore = useSiteStore();
const appTitle = computed(() => siteStore.siteName || "Soga Panel");
const loading = ref(false);
const rememberLogin = ref(false);
const forgotPasswordVisible = ref(false);
const turnstileEl = ref<HTMLElement | null>(null);
const turnstileToken = ref("");

const loginForm = reactive<LoginRequest>({
  email: "",
  password: ""
});

const loginRules: FormRules = {
  email: [
    { required: true, message: "请输入邮箱地址", trigger: "blur" },
    { type: "email", message: "请输入正确的邮箱格式", trigger: "blur" }
  ],
  password: [
    { required: true, message: "请输入密码", trigger: "blur" },
    { min: 6, message: "密码长度不能少于6位", trigger: "blur" }
  ]
};

const googleClientId = (import.meta.env.VITE_GOOGLE_CLIENT_ID || "").toString();
const turnstileSiteKey = (import.meta.env.VITE_TURNSTILE_SITE_KEY || "").toString();
const githubClientId = (import.meta.env.VITE_GITHUB_CLIENT_ID || "").toString();
const googleLoginEnabled = computed(() => Boolean(googleClientId.trim()));
const googleLoading = ref(false);
const githubLoginEnabled = computed(() => Boolean(githubClientId.trim()));
const githubLoading = ref(false);
const turnstileEnabled = computed(() =>
  Boolean((import.meta.env.VITE_TURNSTILE_SITE_KEY || "").toString().trim())
);
const passkeyLoading = ref(false);
const passkeySupported = computed(() => isPasskeySupported());
const oauthTermsRef = ref<InstanceType<typeof TermsAgreement>>();
const pendingOAuthToken = ref("");
const pendingOAuthProvider = ref("第三方");
const oauthTermsHint = "首次使用第三方登录注册账号前需要先阅读并同意服务条款";
const registerMode = ref("1");
const oauthInviteCode = ref("");
const oauthInviteError = ref("");
const inviteRequiredForOAuth = computed(() => registerMode.value === "2");
const inviteQueryCode = computed(() =>
  typeof route.query.invite === "string" ? route.query.invite : ""
);
const showPasswordDialog = ref(false);
const generatedPassword = ref("");
const passwordEmailSent = ref(false);
const redirectAfterDialog = ref(false);
const lastOAuthProvider = ref("Google");
const welcomeTitle = computed(
  () => `欢迎使用 ${lastOAuthProvider.value || "第三方"} 登录`
);
const lastOAuthProviderLabel = computed(
  () => lastOAuthProvider.value || "第三方"
);

const formatProviderLabel = (label: string) => {
  const lower = label?.toLowerCase?.() || "";
  if (lower === "google") return "Google";
  if (lower === "github") return "GitHub";
  return label || "第三方";
};

const requiresTwoFactor = (payload: Partial<LoginResponse>) =>
  Boolean(payload.need2FA ?? payload.need_2fa);

const extractChallengeId = (payload: Partial<LoginResponse>) =>
  (payload.challenge_id || payload.challengeId || "")?.toString() || "";

const completeLogin = (payload: LoginResponse, providerLabel?: string) => {
  if (!payload.token || !payload.user) {
    ElMessage.error("登录响应不完整，请重试");
    return;
  }
  if (payload.trust_token) {
    localStorage.setItem(trustTokenStorageKey, payload.trust_token);
  }
  setToken(payload.token);
  userStore.setUser(payload.user);

  if (payload.user.status === 0) {
    ElMessage.warning("您的账号已被禁用，只能访问仪表盘、公告详情和个人资料页面");
  } else {
    const label = formatProviderLabel(providerLabel || payload.provider || "");
    if (label && label !== "第三方") {
      ElMessage.success(`${label} 登录成功`);
    } else {
      ElMessage.success("登录成功");
    }
  }
};

const handleOAuthPostLogin = (
  providerLabel: string,
  payload: LoginResponse
) => {
  lastOAuthProvider.value = formatProviderLabel(providerLabel);
  rememberLogin.value = Boolean(payload.remember ?? rememberLogin.value);
  passwordEmailSent.value = Boolean(payload.passwordEmailSent);
  generatedPassword.value = payload.tempPassword || "";
  redirectAfterDialog.value = false;

  if (payload.isNewUser && payload.tempPassword) {
    showPasswordDialog.value = true;
    redirectAfterDialog.value = true;
  } else {
    router.push("/dashboard");
  }
};

const navigateAfterLogin = (
  payload: LoginResponse,
  providerLabel?: string
) => {
  const provider = (payload.provider || providerLabel || "").toLowerCase();
  if (provider === "google" || provider === "github") {
    handleOAuthPostLogin(providerLabel || provider, payload);
  } else {
    router.push("/dashboard");
  }
};

const openTwoFactorDialog = (
  payload: Partial<LoginResponse>,
  providerLabel?: string
) => {
  const challengeId = extractChallengeId(payload);
  if (!challengeId) {
    ElMessage.error("未获取到二步验证会话，请重新登录");
    return;
  }
  activeChallengeId.value = challengeId;
  pendingTwoFactorProvider.value = formatProviderLabel(
    providerLabel || payload.provider || "账号"
  );
  twoFactorForm.code = "";
  twoFactorForm.rememberDevice = false;
  twoFactorDialogVisible.value = true;
};

const closeTwoFactorDialog = () => {
  twoFactorDialogVisible.value = false;
  activeChallengeId.value = "";
};

const submitTwoFactor = async () => {
  if (!activeChallengeId.value) {
    ElMessage.error("验证会话已过期，请重新登录");
    twoFactorDialogVisible.value = false;
    return;
  }
  if (!twoFactorForm.code.trim()) {
    ElMessage.warning("请输入验证码");
    return;
  }

  twoFactorSubmitting.value = true;
  try {
    const { data } = await verifyTwoFactor({
      challenge_id: activeChallengeId.value,
      code: twoFactorForm.code.trim(),
      rememberDevice: twoFactorForm.rememberDevice,
      deviceName: pendingTwoFactorProvider.value,
    });
    twoFactorDialogVisible.value = false;
    activeChallengeId.value = "";
    completeLogin(data, pendingTwoFactorProvider.value);
    navigateAfterLogin(data, pendingTwoFactorProvider.value);
  } catch (error) {
    console.error("二步验证失败:", error);
    ElMessage.error((error as any)?.message || "二步验证失败，请重试");
  } finally {
    twoFactorSubmitting.value = false;
  }
};

const requestOAuthAgreement = (
  providerLabel: string,
  pendingToken: string,
) => {
  pendingOAuthToken.value = pendingToken;
  pendingOAuthProvider.value = providerLabel;
  oauthInviteError.value = "";
  oauthInviteCode.value = inviteQueryCode.value || "";
  oauthTermsRef.value?.openDialog();
  ElMessage.warning(oauthTermsHint);
};

const handleOAuthTermsAccepted = async () => {
  if (!pendingOAuthToken.value) return;
  const trimmedCode = oauthInviteCode.value.trim();
  if (inviteRequiredForOAuth.value && !trimmedCode) {
    oauthInviteError.value = "请输入邀请码";
    ElMessage.warning("请输入邀请码");
    return;
  }
  try {
    const payload: { pendingToken: string; inviteCode?: string } = {
      pendingToken: pendingOAuthToken.value
    };
    if (trimmedCode) {
      payload.inviteCode = trimmedCode;
    }
    const { data } = await completePendingOAuthRegistration(payload);
    const providerLabel = pendingOAuthProvider.value || "第三方";
    pendingOAuthToken.value = "";
    pendingOAuthProvider.value = "第三方";
    oauthInviteCode.value = "";
    oauthInviteError.value = "";
    handleOAuthLoginSuccess(providerLabel, data as OAuthLoginPayload);
  } catch (error) {
    console.error("完成 OAuth 注册失败:", error);
    ElMessage.error((error as any)?.message || "完成注册失败，请稍后重试");
  }
};

const handleOAuthTermsDeclined = () => {
  pendingOAuthToken.value = "";
  pendingOAuthProvider.value = "第三方";
  oauthInviteError.value = "";
  ElMessage.warning("不同意服务条款无法自动注册账号");
};

const googleButtonConfig = {
  type: "icon",
  theme: "outline",
  size: "large",
  shape: "circle"
} as const;

const handleGoogleClick = () => {
  if (!googleLoginEnabled.value) {
    ElMessage.warning("暂未配置 Google 登录，请联系管理员");
    return;
  }
};

const githubStateStorageKey = "github_oauth_state";
const githubRememberStorageKey = "github_oauth_remember";
const trustTokenStorageKey = "soga_tf_trust_token";
const telegramScriptId = "telegram-web-app-sdk";
const telegramAutoLoginLoading = ref(false);
const safeGetSessionStorageItem = (key: string): string | null => {
  try {
    return sessionStorage.getItem(key);
  } catch (error) {
    console.warn(`读取 sessionStorage 失败: ${key}`, error);
    return null;
  }
};
const safeSetSessionStorageItem = (key: string, value: string): boolean => {
  try {
    sessionStorage.setItem(key, value);
    return true;
  } catch (error) {
    console.warn(`写入 sessionStorage 失败: ${key}`, error);
    return false;
  }
};
const safeRemoveSessionStorageItem = (key: string): void => {
  try {
    sessionStorage.removeItem(key);
  } catch (error) {
    console.warn(`移除 sessionStorage 失败: ${key}`, error);
  }
};
const clearGithubOAuthSessionState = () => {
  safeRemoveSessionStorageItem(githubStateStorageKey);
  safeRemoveSessionStorageItem(githubRememberStorageKey);
};
const shouldAttemptTelegramMiniAppLogin = computed(() => {
  const raw = route.query.tgMiniApp;
  if (Array.isArray(raw)) {
    return raw.some((item) => String(item).trim() === "1");
  }
  return String(raw ?? "").trim() === "1";
});

const twoFactorDialogVisible = ref(false);
const twoFactorSubmitting = ref(false);
const twoFactorForm = reactive({
  code: "",
  rememberDevice: false
});
const activeChallengeId = ref("");
const pendingTwoFactorProvider = ref("账号");

const createOAuthState = (length = 16) => {
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  return Math.random().toString(36).slice(2, 2 + length);
};

const handleGithubClick = () => {
  if (!githubLoginEnabled.value) {
    ElMessage.warning("暂未配置 GitHub 登录，请联系管理员");
    return;
  }
  startGithubOAuth();
};

const startGithubOAuth = () => {
  const state = createOAuthState(12);
  const stateStored = safeSetSessionStorageItem(githubStateStorageKey, state);
  if (!stateStored) {
    ElMessage.error("当前环境限制会话存储，暂时无法使用 GitHub 登录");
    return;
  }
  safeSetSessionStorageItem(
    githubRememberStorageKey,
    rememberLogin.value ? "1" : "0"
  );
  const redirectUri = `${window.location.origin}/auth/login?provider=github`;
  const params = new URLSearchParams({
    client_id: githubClientId,
    scope: "read:user user:email",
    state,
    allow_signup: "true",
    redirect_uri: redirectUri,
  });
  window.location.href = `https://github.com/login/oauth/authorize?${params.toString()}`;
};

type OAuthLoginPayload = LoginResponse & {
  isNewUser?: boolean;
  tempPassword?: string | null;
  passwordEmailSent?: boolean;
  pendingTermsToken?: string;
};

const handleOAuthLoginSuccess = (
  providerLabel: string,
  payload: OAuthLoginPayload
) => {
  const pendingToken =
    payload.pendingTermsToken || (payload as any)?.pending_terms_token;
  if (pendingToken) {
    requestOAuthAgreement(
      providerLabel,
      pendingToken
    );
    return;
  }

  if (requiresTwoFactor(payload)) {
    localStorage.removeItem(trustTokenStorageKey);
    openTwoFactorDialog(payload, providerLabel);
    return;
  }

  finalizeOAuthLogin(providerLabel, payload);
};

const finalizeOAuthLogin = (
  providerLabel: string,
  payload: OAuthLoginPayload
) => {
  completeLogin(payload, providerLabel);
  handleOAuthPostLogin(providerLabel, payload);
};

const performGoogleLogin = async (credential: string) => {
  if (!credential) return;
  if (googleLoading.value) return;
  googleLoading.value = true;

  try {
    const storedTrustToken = localStorage.getItem(trustTokenStorageKey) || "";
    const { data } = await loginWithGoogle({
      idToken: credential,
      remember: rememberLogin.value,
      twoFactorTrustToken: storedTrustToken || undefined
    });
    handleOAuthLoginSuccess("Google", data as OAuthLoginPayload);
  } catch (error) {
    console.error("Google 登录失败:", error);
    ElMessage.error((error as any)?.message || "Google 登录失败，请稍后重试");
  } finally {
    googleLoading.value = false;
  }
};

const performGithubLogin = async ({
  code,
  state,
  remember
}: {
  code: string;
  state: string;
  remember: boolean;
}) => {
  githubLoading.value = true;
  try {
    const redirectUri = `${window.location.origin}/auth/login`;
    const storedTrustToken = localStorage.getItem(trustTokenStorageKey) || "";
    const { data } = await loginWithGithub({
      code,
      redirectUri,
      state,
      remember,
      twoFactorTrustToken: storedTrustToken || undefined
    });
    handleOAuthLoginSuccess(
      (data as any)?.provider || "GitHub",
      data as OAuthLoginPayload
    );
  } catch (error) {
    console.error("GitHub 登录失败:", error);
    ElMessage.error((error as any)?.message || "GitHub 登录失败，请稍后重试");
  } finally {
    githubLoading.value = false;
  }
};

const handleLogin = async () => {
  if (!loginFormRef.value) return;

  const valid = await loginFormRef.value.validate().catch(() => false);
  if (!valid) return;

  if (turnstileEnabled.value && !turnstileToken.value) {
    ElMessage.warning("请先完成人机验证");
    return;
  }

  loading.value = true;

  try {
    const storedTrustToken = localStorage.getItem(trustTokenStorageKey) || "";
    const { data } = await login({
      email: loginForm.email,
      password: loginForm.password,
      remember: rememberLogin.value,
      turnstileToken: turnstileToken.value || undefined,
      twoFactorTrustToken: storedTrustToken || undefined,
    });

    if (requiresTwoFactor(data)) {
      localStorage.removeItem(trustTokenStorageKey);
      openTwoFactorDialog(data, "账号");
      return;
    }

    completeLogin(data, "账号");
    navigateAfterLogin(data, "账号");
  } catch (error) {
    console.error("登录失败:", error);
    ElMessage.error((error as any)?.message || "登录失败，请稍后重试");
  } finally {
    loading.value = false;
  }
};

const handlePasskeyLogin = async () => {
  const email = loginForm.email.trim().toLowerCase();
  if (!passkeySupported.value) {
    ElMessage.warning("当前浏览器不支持通行密钥，请使用密码或更换设备");
    return;
  }
  if (!email) {
    ElMessage.warning("请输入邮箱后再使用通行密钥登录");
    return;
  }
  passkeyLoading.value = true;
  try {
    const { data } = await getPasskeyLoginOptions({
      email,
      remember: rememberLogin.value
    });
    if (!data?.challenge) {
      throw new Error("未获取到通行密钥挑战");
    }
    if (!data?.allowCredentials || data.allowCredentials.length === 0) {
      ElMessage.warning("该账户未绑定通行密钥，请先在个人资料中绑定");
      return;
    }
    const credential = await performPasskeyLogin(data);
    const { data: result } = await verifyPasskeyLogin({ credential });
    completeLogin(result, "通行密钥");
    navigateAfterLogin(result, "通行密钥");
  } catch (error) {
    console.error("通行密钥登录失败:", error);
    ElMessage.error((error as any)?.message || "通行密钥登录失败，请稍后重试");
  } finally {
    passkeyLoading.value = false;
  }
};

const goToRegister = () => {
  router.push("/register");
};

const goToForgotPassword = () => {
  router.push("/auth/forgot-password");
};

interface GoogleCredentialResponse {
  credential?: string;
}

const handleGoogleCredential = async (
  googleResponse: GoogleCredentialResponse
) => {
 if (!googleLoginEnabled.value) {
    ElMessage.warning("暂未配置 Google 登录，请联系管理员");
    return;
  }

  const credential = googleResponse?.credential;
  if (!credential) {
    ElMessage.error("未获取到 Google 登录凭证，请重试");
    return;
  }

  await performGoogleLogin(credential);
};

const handlePasswordDialogClose = () => {
  showPasswordDialog.value = false;
  if (redirectAfterDialog.value) {
    redirectAfterDialog.value = false;
    router.push("/dashboard");
  }
};

const processGithubCallback = async () => {
  const provider = typeof route.query.provider === "string" ? route.query.provider : "";
  const code = typeof route.query.code === "string" ? route.query.code : "";
  const returnedState = typeof route.query.state === "string" ? route.query.state : "";
  const error = typeof route.query.error === "string" ? route.query.error : "";

  const expectedState = safeGetSessionStorageItem(githubStateStorageKey);
  const rememberFlag =
    safeGetSessionStorageItem(githubRememberStorageKey) === "1";
  rememberLogin.value = rememberFlag;

  if (provider !== "github" && !expectedState) return;

  if (!githubLoginEnabled.value) {
    ElMessage.warning("暂未配置 GitHub 登录，请联系管理员");
    clearGithubOAuthSessionState();
    return;
  }

  const cleanQuery = { ...route.query } as Record<string, any>;
  delete cleanQuery.provider;
  delete cleanQuery.code;
  delete cleanQuery.state;
  delete cleanQuery.error;
  router.replace({ path: route.path, query: cleanQuery }).catch(() => undefined);

  if (error) {
    ElMessage.error("GitHub 授权被取消或失败");
    clearGithubOAuthSessionState();
    return;
  }

  if (!code) {
    clearGithubOAuthSessionState();
    return;
  }

  clearGithubOAuthSessionState();

  if (expectedState && returnedState && expectedState !== returnedState) {
    ElMessage.error("GitHub 登录状态校验失败，请重试");
    return;
  }

  const githubPayload = {
    code,
    state: returnedState,
    remember: rememberFlag
  };

  await performGithubLogin(githubPayload);
};

const loadTelegramWebAppSdk = async () => {
  if (typeof window === "undefined") return;
  if ((window as any).Telegram?.WebApp) return;

  await new Promise<void>((resolve, reject) => {
    const existing = document.getElementById(
      telegramScriptId
    ) as HTMLScriptElement | null;
    if (existing) {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener(
        "error",
        () => reject(new Error("Telegram SDK 加载失败")),
        { once: true }
      );
      return;
    }

    const script = document.createElement("script");
    script.id = telegramScriptId;
    script.src = "https://telegram.org/js/telegram-web-app.js";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Telegram SDK 加载失败"));
    document.head.appendChild(script);
  });
};

const getTelegramMiniAppInitData = () => {
  const webApp = (window as any).Telegram?.WebApp;
  if (!webApp) return "";
  try {
    webApp.ready?.();
    webApp.expand?.();
  } catch (error) {
    console.warn("Telegram WebApp ready/expand 调用失败", error);
  }
  return (webApp.initData || "").toString().trim();
};

const tryTelegramMiniAppLogin = async () => {
  if (!shouldAttemptTelegramMiniAppLogin.value) return;
  if (telegramAutoLoginLoading.value) return;
  telegramAutoLoginLoading.value = true;

  try {
    await loadTelegramWebAppSdk();
    const initData = getTelegramMiniAppInitData();
    if (!initData) {
      ElMessage.warning("未获取到 Telegram Mini App 授权数据，请从机器人重新打开面板");
      return;
    }

    const storedTrustToken = localStorage.getItem(trustTokenStorageKey) || "";
    const { data } = await loginWithTelegramMiniApp({
      initData,
      remember: true,
      twoFactorTrustToken: storedTrustToken || undefined,
    });

    if (requiresTwoFactor(data)) {
      localStorage.removeItem(trustTokenStorageKey);
      openTwoFactorDialog(data, "Telegram");
      return;
    }

    completeLogin(data, "Telegram");
    navigateAfterLogin(data, "Telegram");
  } catch (error) {
    console.error("Telegram Mini App 登录失败:", error);
    ElMessage.error((error as any)?.message || "Telegram Mini App 登录失败，请稍后重试");
  } finally {
    telegramAutoLoginLoading.value = false;
  }
};

const loadAuthConfig = async () => {
  try {
    const { data } = await getRegisterConfig();
    forgotPasswordVisible.value = Boolean(data?.passwordResetEnabled);
    registerMode.value = data?.registerMode || "1";
  } catch (error) {
    console.error("获取认证配置失败:", error);
    forgotPasswordVisible.value = false;
  }
};

onMounted(() => {
  void loadAuthConfig().catch((error) => {
    console.warn("初始化认证配置失败:", error);
  });
  void processGithubCallback().catch((error) => {
    console.warn("处理 GitHub OAuth 回调失败:", error);
  });
  void tryTelegramMiniAppLogin().catch((error) => {
    console.warn("执行 Telegram Mini App 自动登录失败:", error);
  });
  if (turnstileEnabled.value && typeof window !== "undefined") {
    const scriptId = "cf-turnstile-script";
    const existingScript = document.getElementById(scriptId);
    const renderTurnstile = () => {
      if (!window.turnstile || !turnstileEl.value) return;
      window.turnstile.render(turnstileEl.value, {
        sitekey: turnstileSiteKey,
        callback(token: string) {
          turnstileToken.value = token;
        },
        "error-callback"() {
          turnstileToken.value = "";
        },
        "expired-callback"() {
          turnstileToken.value = "";
        }
      });
    };

    if (window.turnstile) {
      renderTurnstile();
    } else if (!existingScript) {
      const script = document.createElement("script");
      script.id = scriptId;
      script.src =
        "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
      script.async = true;
      script.defer = true;
      script.onload = () => {
        renderTurnstile();
      };
      script.onerror = () => {
        console.error("Turnstile 脚本加载失败");
      };
      document.head.appendChild(script);
    } else {
      existingScript.addEventListener("load", () => renderTurnstile(), {
        once: true
      });
    }
  }
});

const copyGeneratedPassword = async () => {
  if (!generatedPassword.value) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(generatedPassword.value);
    } else {
      const textarea = document.createElement("textarea");
      textarea.value = generatedPassword.value;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }
    ElMessage.success("密码已复制到剪贴板");
  } catch (error) {
    console.error("复制密码失败:", error);
    ElMessage.warning("复制失败，请手动复制密码");
  }
};
</script>

<style scoped lang="scss">
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: #f7f9fc;
  padding: 40px 16px;
}

.login-panel {
  width: 380px;
  background: #ffffff;
  border-radius: 18px;
  box-shadow: 0 20px 60px rgba(79, 70, 229, 0.08);
  padding: 36px 40px 32px;
  position: relative;
}

.brand {
  text-align: center;
  margin-bottom: 28px;
}

.brand-logo {
  width: 64px;
  height: 64px;
  line-height: 64px;
  margin: 0 auto 12px;
  border-radius: 20px;
  font-size: 28px;
  font-weight: 700;
  color: #ffffff;
  background: linear-gradient(135deg, #5a6cea 0%, #8f44fd 100%);
  box-shadow: 0 12px 25px rgba(122, 111, 250, 0.22);
}

.brand-title {
  font-size: 26px;
  font-weight: 600;
  color: #374151;
  letter-spacing: 1px;
}

.login-form {
  :deep(.el-input__wrapper) {
    border-radius: 10px;
    box-shadow: none;
    border: 1px solid #e5e7eb;
    padding: 0 14px;
    transition: border-color 0.2s ease;
  }

  :deep(.el-input__wrapper.is-focus) {
    border-color: #5a6cea;
    box-shadow: 0 0 0 3px rgba(90, 108, 234, 0.15);
  }

  :deep(.el-input__inner) {
    font-size: 15px;
  }
}

.form-options {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin: 4px 0 16px;

  :deep(.el-checkbox) {
    --el-checkbox-font-weight: 500;
  }
}

.submit-btn {
  width: 100%;
  height: 44px;
  font-size: 15px;
  font-weight: 600;
  border-radius: 12px;
  background: linear-gradient(135deg, #5a6cea 0%, #7c3aed 100%);
  border: none;
}

.register-action {
  display: flex;
  justify-content: center;
  margin: 18px 0 12px;

  :deep(.el-button) {
    width: 60%;
    border-radius: 10px;
    font-size: 14px;
    color: #4b5563;
  }
}

.third-party {
  margin-top: 12px;
}

.third-title {
  text-align: center;
  color: #9ca3af;
  font-size: 13px;
  position: relative;
  margin-bottom: 18px;
}

.third-title span {
  display: inline-block;
  padding: 0 20px;
  position: relative;
}

.third-title span::before,
.third-title span::after {
  content: "";
  position: absolute;
  top: 50%;
  width: 60px;
  height: 1px;
  background: rgba(156, 163, 175, 0.45);
}

.third-title span::before {
  right: 100%;
  margin-right: 18px;
}

.third-title span::after {
  left: 100%;
  margin-left: 18px;
}

.third-icons {
  display: flex;
  justify-content: center;
  gap: 22px;
}

.turnstile-container {
  margin-top: 16px;
  display: flex;
  justify-content: center;
}

.cf-turnstile-placeholder {
  min-height: 65px;
}

.third-icon {
  position: relative;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  border: 2px solid #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #fff;
}

.third-icon.google:hover {
  border-color: #cbd5f5;
  box-shadow: 0 6px 18px rgba(148, 163, 184, 0.18);
}

.third-icon.github {
  color: #1f2937;
}

.third-icon.github:hover {
  border-color: #d1d5db;
  box-shadow: 0 6px 18px rgba(99, 102, 241, 0.12);
}

.third-icon.passkey {
  border-color: #e2e8f0;
  background: #f8fafc;
}

.third-icon.passkey:hover:not(.disabled) {
  border-color: #cbd5f5;
  box-shadow: 0 6px 18px rgba(79, 70, 229, 0.14);
}

.third-icon.passkey.disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.icon-wrapper {
  pointer-events: none;
  display: flex;
  align-items: center;
}

.placeholder-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #cbd5f5;
  box-shadow: 10px 0 0 #cbd5f5, -10px 0 0 #cbd5f5;
}

.placeholder {
  border-style: dashed;
  color: #cbd5f5;
}

.google-trigger {
  position: absolute !important;
  inset: 0;
  opacity: 0;
  cursor: pointer;
}

.register-tip {
  margin-top: 22px;
  text-align: center;
  color: #6b7280;
  font-size: 14px;
}

.password-dialog-text {
  margin-bottom: 12px;
  color: #4b5563;
  line-height: 1.6;
}

.password-display {
  margin-bottom: 10px;

  :deep(.el-input__wrapper) {
    background: #f9fafb;
    border-radius: 10px;
    border: 1px dashed #d1d5db;
  }
}

.password-dialog-tip {
  margin-top: 6px;
  color: #6b7280;
  font-size: 14px;
}

.twofactor-tip {
  font-size: 13px;
  color: #6b7280;
  margin-bottom: 12px;
}

.twofactor-form :deep(.el-form-item) {
  margin-bottom: 12px;
}

.oauth-loading {
  position: absolute;
  inset: 0;
  border-radius: 50%;
  background: rgba(255, 255, 255, 0.8);
  display: flex;
  align-items: center;
  justify-content: center;

  .el-icon {
    color: #4f46e5;
  }
}

.oauth-invite-block {
  margin-bottom: 16px;

  .oauth-invite-label {
    font-size: 13px;
    color: #4b5563;
    margin-bottom: 6px;

    .required-indicator {
      color: #ef4444;
      margin-left: 4px;
    }
  }

  .oauth-invite-tip {
    font-size: 12px;
    color: #9ca3af;
    margin-top: 6px;
  }
}

.oauth-invite-error {
  color: #ef4444;
  font-size: 12px;
  margin-top: 4px;
}
</style>

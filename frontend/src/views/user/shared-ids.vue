<template>
  <div class="user-page user-shared-ids">
    <div class="page-header">
      <div>
        <h2>苹果账号</h2>
        <p>本站对符合要求的会员提供部分软件的ID共享账号以满足部分会员的需求。</p>
      </div>
      <div class="actions">
        <el-button :icon="RefreshRight" :loading="loading" @click="fetchSharedIds">刷新</el-button>
      </div>
    </div>

    <section class="instructions-card">
      <div class="instructions-layout">
        <div class="warning-panel">
          <div class="warning-title">
            <el-icon><WarningFilled /></el-icon>
            使用须知
          </div>
          <ul class="warning-list">
            <li>第一步:打开 App Store</li>
            <li>第二步:点击右上角头像</li>
            <li>第三步:滑动到底部退出登录</li>
            <li>第四步:登录共享账号</li>
            <li>第五步:其他选项 不升级</li>
            <li>成功登录，下载完App后立马退出账号!</li>
            <li>禁止在设置里登录</li>
            <li>禁止登陆iCloud</li>
            <li>禁止绑定手机号</li>
            <li>共享账号一旦锁定将无法在设置登出</li>
            <li>登陆iCloud造成手机被锁定或照片泄露后果自负</li>
          </ul>
        </div>
        <div class="guide-panel">
          <div class="guide-image">
            <img src="/appleid.jpeg" alt="苹果账号登录步骤" />
          </div>
        </div>
      </div>
    </section>

    <div v-loading="loading">
      <el-empty v-if="!loading && sharedIds.length === 0" description="暂无苹果账号配置" />
      <el-row v-else :gutter="16" class="shared-id-list">
        <el-col v-for="item in sharedIds" :key="item.id" :xs="24" :sm="12" :lg="8">
          <el-card class="shared-card" shadow="hover">
            <div class="card-header">
              <div class="title">
                <el-icon><Key /></el-icon>
                <span>{{ item.name }}</span>
              </div>
              <el-tag :type="getStatusTagType(item)" size="small">{{ getStatusText(item) }}</el-tag>
            </div>

            <div class="card-body" v-if="item.status === 'ok' && getAccountList(item).length > 0">
              <div v-if="item.missing_ids?.length" class="missing-tip">
                未匹配 ID：{{ item.missing_ids.join(', ') }}
              </div>
              <div
                class="account-block"
                v-for="(account, index) in getAccountList(item)"
                :key="index"
              >
                <div class="account-title" v-if="getAccountList(item).length > 1">
                  <span>账号 {{ index + 1 }}</span>
                  <span class="account-id" v-if="getAccountField(account, 'id') !== '-'">
                    ID：{{ getAccountField(account, 'id') }}
                  </span>
                </div>
                <div class="info-row">
                  <span>账号</span>
                  <div class="value">
                    <span>{{ getAccountField(account, 'username') }}</span>
                    <el-button link size="small" @click="copyField(account, 'username')">复制</el-button>
                  </div>
                </div>
                <div class="info-row">
                  <span>密码</span>
                  <div class="value">
                    <span class="password">********</span>
                    <el-button link size="small" @click="copyField(account, 'password')">复制</el-button>
                  </div>
                </div>
                <div class="info-row" v-if="getAccountField(account, 'region_display') !== '-'">
                  <span>区域</span>
                  <div class="value">{{ getAccountField(account, 'region_display') }}</div>
                </div>
                <div class="info-row" v-if="getAccountField(account, 'message') !== '-'">
                  <span>状态</span>
                  <div class="value">{{ getAccountField(account, 'message') }}</div>
                </div>
                <div class="info-row" v-if="getAccountField(account, 'last_check') !== '-'">
                  <span>最近检测</span>
                  <div class="value">{{ getAccountField(account, 'last_check') }}</div>
                </div>
              </div>
            </div>

            <el-empty
              v-else-if="item.status === 'missing'"
              description="未在远程响应中找到对应ID"
              :image-size="80"
            />

            <el-alert v-else type="error" :closable="false" show-icon>
              <template #title>
                {{ item.error || '远程接口请求失败' }}
              </template>
            </el-alert>

            <div class="card-footer">
              <span v-if="item.fetched_at">最近同步：{{ formatTime(item.fetched_at) }}</span>
            </div>
          </el-card>
        </el-col>
      </el-row>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from "vue";
import { ElMessage } from "element-plus";
import { RefreshRight, Key, WarningFilled } from "@element-plus/icons-vue";
import { getUserSharedIds, type SharedIdItem } from "@/api/user";

const sharedIds = ref<SharedIdItem[]>([]);
const loading = ref(false);

const fetchSharedIds = async () => {
  loading.value = true;
  try {
    const { data } = await getUserSharedIds();
    sharedIds.value = data?.items ?? [];
  } catch (error) {
    console.error(error);
    ElMessage.error("获取苹果账号失败");
  } finally {
    loading.value = false;
  }
};

const getStatusTagType = (item: SharedIdItem) => {
  if (item.status === "ok" && item.missing_ids?.length) return "warning";
  switch (item.status) {
    case "ok":
      return "success";
    case "missing":
      return "warning";
    default:
      return "danger";
  }
};

const getStatusText = (item: SharedIdItem) => {
  if (item.status === "ok") return item.missing_ids?.length ? "部分可用" : "可用";
  if (item.status === "missing") return "未匹配";
  return "拉取失败";
};

const getAccountList = (item: SharedIdItem): Record<string, unknown>[] => {
  if (Array.isArray(item.accounts) && item.accounts.length > 0) return item.accounts;
  if (item.account) return [item.account];
  return [];
};

const getAccountField = (account: Record<string, unknown> | null, key: string): string => {
  if (!account) return "-";
  const value = account[key];
  if (value === null || value === undefined) return "-";
  if (typeof value === "number") return value.toString();
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
};

const copyField = async (account: Record<string, unknown> | null, key: string) => {
  const value = getAccountField(account, key);
  if (!value || value === "-") {
    ElMessage.warning("没有可复制的内容");
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
    ElMessage.success("已复制到剪贴板");
  } catch (error) {
    console.error(error);
    ElMessage.error("复制失败，请手动复制");
  }
};

const formatTime = (time?: string) => {
  if (!time) return "-";
  const date = new Date(time);
  if (Number.isNaN(date.getTime())) return time;
  return date.toLocaleString();
};

onMounted(fetchSharedIds);
</script>

<style scoped lang="scss">
.user-shared-ids {
  .actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

.instructions-card {
    margin: 16px 0 32px;
    padding: 24px;
    border-radius: 16px;
    background: linear-gradient(135deg, #fdfcff 0%, #f3f8ff 45%, #fff8f2 100%);
    border: 1px solid rgba(64, 158, 255, 0.2);
    box-shadow: 0 12px 32px rgba(15, 58, 116, 0.08);
  }

.instructions-layout {
  width: 90%;
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  align-items: flex-start;
}

  .warning-panel {
    flex: 1 1 280px;
    max-width: 380px;
    background: rgba(255, 247, 240, 0.95);
    border-radius: 12px;
    padding: 20px 24px 24px;
    border: 1px solid rgba(255, 125, 69, 0.2);

    .warning-title {
      display: flex;
      align-items: center;
      font-weight: 600;
      color: #c45656;
      margin-bottom: 12px;

      .el-icon {
        margin-right: 6px;
        font-size: 18px;
      }
    }

    .warning-list {
      margin: 0;
      padding-left: 20px;
      color: #d36d47;
      line-height: 1.8;
      font-size: 14px;
    }
  }

  .guide-panel {
    flex: 2.5 1 520px;
    display: flex;
    flex-direction: column;
    margin-bottom: 20px;

    h3 {
      align-self: flex-start;
      margin: 0 0 8px;
      font-size: 20px;
      color: #1f2d3d;
    }
    p {
      align-self: flex-start;
      margin: 0 0 16px;
      color: #606266;
    }

    .guide-image {
      width: 100%;
      border-radius: 16px;
      overflow: hidden;
      border: 1px solid rgba(64, 158, 255, 0.2);
      box-shadow: 0 12px 24px rgba(15, 58, 116, 0.08);
      background: #fff;
      padding: 16px;

      img {
        width: 100%;
        display: block;
      }
    }
  }

  @media (max-width: 768px) {
    .instructions-layout {
      flex-direction: column;
      align-items: stretch;
    }

    .warning-panel,
    .guide-panel {
      max-width: 100%;
      flex: none;
      width: 100%;
    }

    .guide-panel {
      margin-bottom: 16px;
    }
  }

  .shared-card {
    margin-bottom: 24px;

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;

      .title {
        display: flex;
        align-items: center;
        font-weight: 600;
        gap: 6px;

        .el-icon {
          color: #409eff;
        }
      }
    }

	    .card-body {
	      .missing-tip {
	        margin-bottom: 10px;
	        font-size: 12px;
	        color: #e6a23c;
	      }

	      .account-block + .account-block {
	        margin-top: 12px;
	        padding-top: 12px;
	        border-top: 1px dashed rgba(144, 147, 153, 0.35);
	      }

	      .account-title {
	        display: flex;
	        justify-content: space-between;
	        align-items: center;
	        margin-bottom: 6px;
	        font-size: 12px;
	        color: #606266;

	        .account-id {
	          color: #909399;
	        }
	      }

	      .info-row {
	        display: flex;
	        justify-content: space-between;
	        padding: 6px 0;
	        font-size: 14px;

        .value {
          display: flex;
          gap: 8px;
          align-items: center;
          color: #303133;

          .password {
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
          }
        }
      }
    }

    .card-footer {
      margin-top: 12px;
      font-size: 12px;
      color: #909399;
      display: flex;
      justify-content: space-between;
    }
  }

  .shared-id-list {
    padding-bottom: 24px;
  }
}
</style>

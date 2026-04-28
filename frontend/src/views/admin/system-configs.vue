<template>
  <div class="system-configs-container">
    <!-- 配置详情表格 -->
    <el-card v-loading="loading">
      <template #header>
        <span>系统配置管理</span>
      </template>

      <el-table
        :data="configList"
        row-key="key"
        stripe
        :header-cell-style="tableHeaderCellStyle"
      >
        <el-table-column prop="key" label="配置键" min-width="220" show-overflow-tooltip />
        <el-table-column prop="value" label="当前值" min-width="240">
          <template #default="scope">
            <el-input
              v-if="isEditing(scope.row.key)"
              v-model="scope.row.editValue"
              :type="getInputType(scope.row.key)"
              size="small"
              @keyup.enter="handleSaveEdit(scope.row)"
            >
              <template #append v-if="getUnit(scope.row.key)">
                {{ getUnit(scope.row.key) }}
              </template>
            </el-input>
            <span v-else>{{ scope.row.value }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="说明" min-width="300" show-overflow-tooltip />
        <el-table-column label="操作" width="140" fixed="right">
          <template #default="scope">
            <el-button
              v-if="!isEditing(scope.row.key)"
              class="reset-margin"
              link
              type="primary"
              @click="handleStartEdit(scope.row)"
            >
              修改
            </el-button>
            <div v-else class="operation-actions">
              <el-button
                class="reset-margin"
                link
                type="primary"
                :loading="isSaving(scope.row.key)"
                @click="handleSaveEdit(scope.row)"
              >
                保存
              </el-button>
              <el-button
                class="reset-margin"
                link
                @click="handleCancelEdit(scope.row)"
              >
                取消
              </el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>

      <div class="config-hints" v-if="configList.length > 0">
        <el-alert 
          title="配置说明" 
          type="info" 
          :closable="false"
          show-icon
        >
          <ul>
            <li><strong>default_traffic</strong>: 默认10GB = 10737418240 字节</li>
            <li><strong>traffic_reset_day</strong>: 0表示不执行每月定时任务，1-31表示每月几号重置流量</li>
            <li><strong>register_enabled</strong>: 0=禁用，1=开放注册，2=仅允许邀请码注册</li>
            <li><strong>default_class</strong>: 新用户默认等级，数字越大权限越高</li>
            <li><strong>register_email_verification_enabled</strong>: 1 开启注册验证码，0 可关闭此功能</li>
            <li><strong>message_queue_page_size</strong>: 消息队列每分钟发送条数（用于邮件/Bark/Telegram 等通知限速）</li>
            <li><strong>telegram_bot_token</strong>: Telegram 机器人 Token（格式如 123456:ABC...）</li>
            <li><strong>telegram_bot_api_base</strong>: Telegram API 基础地址（默认 https://api.telegram.org）</li>
            <li><strong>telegram_bot_username</strong>: 机器人用户名（不含 @，用于生成一键绑定链接）</li>
            <li><strong>telegram_webhook_secret</strong>: Webhook 请求头校验密钥（可选）</li>
            <li><strong>telegram_miniapp_url</strong>: Telegram Mini App 打开地址（为空时自动使用 site_url）</li>
            <li><strong>rebate_rate</strong>: 邀请返利比例，0.1 表示 10%</li>
            <li><strong>rebate_mode</strong>: first_order=首单返利，every_order=每笔返利</li>
            <li><strong>invite_default_limit</strong>: 默认邀请码可使用次数（0 表示不限）</li>
            <li><strong>rebate_withdraw_fee_rate</strong>: 返利提现手续费比例（0.05 表示 5%）</li>
            <li><strong>rebate_withdraw_min_amount</strong>: 返利提现最低金额（元）</li>
          </ul>
        </el-alert>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import {
  getSystemConfigs,
  updateSystemConfig,
  type SystemConfig
} from '@/api/admin'

interface ExtendedSystemConfig extends SystemConfig {
  editValue: string
}

interface EditState {
  editable: boolean
  saving: boolean
  snapshot: string
}

const loading = ref(false)
const configList = ref<ExtendedSystemConfig[]>([])
const editMap = ref<Record<string, EditState>>({})
const editingKey = ref('')

const tableHeaderCellStyle = {
  background: 'var(--el-fill-color-light)',
  color: 'var(--el-text-color-primary)'
}

const isEditing = (key: string) => Boolean(editMap.value[key]?.editable)
const isSaving = (key: string) => Boolean(editMap.value[key]?.saving)

const resetEditingByKey = (key: string) => {
  if (!key) return
  const target = configList.value.find(item => item.key === key)
  const state = editMap.value[key]
  if (target && state) {
    target.editValue = state.snapshot
  }
  delete editMap.value[key]
  if (editingKey.value === key) {
    editingKey.value = ''
  }
}

// 获取系统配置
const fetchConfigs = async () => {
  try {
    loading.value = true
    const response = await getSystemConfigs()
    const configs = Array.isArray(response.data) ? response.data : []

    // 初始化扩展属性
    configList.value = configs.map(config => ({
      ...config,
      editValue: config.value || ''
    }))
    editMap.value = {}
    editingKey.value = ''
  } catch (error: any) {
    ElMessage.error(error.message || '获取系统配置失败')
    configList.value = []
  } finally {
    loading.value = false
  }
}

// 开始编辑
const handleStartEdit = (config: ExtendedSystemConfig) => {
  if (editingKey.value && editingKey.value !== config.key) {
    resetEditingByKey(editingKey.value)
  }

  config.editValue = config.value || ''
  editMap.value[config.key] = {
    editable: true,
    saving: false,
    snapshot: config.value || ''
  }
  editingKey.value = config.key
}

// 取消编辑
const handleCancelEdit = (config: ExtendedSystemConfig) => {
  resetEditingByKey(config.key)
}

// 保存编辑
const handleSaveEdit = async (config: ExtendedSystemConfig) => {
  const state = editMap.value[config.key]
  if (!state?.editable) {
    return
  }

  try {
    state.saving = true
    const nextValue = config.editValue || ''

    await updateSystemConfig({
      key: config.key,
      value: nextValue
    })

    config.value = nextValue
    resetEditingByKey(config.key)
    ElMessage.success(`${config.description || config.key} 保存成功`)
  } catch (error: any) {
    ElMessage.error(error.message || '保存失败')
  } finally {
    const currentState = editMap.value[config.key]
    if (currentState) {
      currentState.saving = false
    }
  }
}

// 获取输入框类型
const getInputType = (key: string) => {
  if (
    key.includes('traffic') ||
    key.includes('expire_days') ||
    key.includes('class') ||
    key.includes('reset_day') ||
    key.includes('page_size') ||
    key.endsWith('_amount') ||
    key.endsWith('_rate')
  ) {
    return 'number'
  }
  if (key.includes('url')) {
    return 'url'
  }
  if (key.includes('email')) {
    return 'email'
  }
  return 'text'
}

// 获取单位
const getUnit = (key: string) => {
  if (key.includes('traffic') && !key.includes('reset')) {
    return '字节'
  }
  if (key.includes('expire_days') || key.includes('reset_day')) {
    return '天'
  }
  if (key.endsWith('_amount')) {
    return '元'
  }
  if (key.includes('page_size')) {
    return '条/分钟'
  }
  return ''
}


onMounted(() => {
  fetchConfigs()
})
</script>

<style lang="scss" scoped>
.system-configs-container {
  .reset-margin {
    margin-left: 0 !important;
  }

  .operation-actions {
    display: inline-flex;
    align-items: center;
    gap: 12px;
  }

  .config-hints {
    margin-top: 16px;
    
    :deep(.el-alert__content) {
      ul {
        margin: 8px 0;
        padding-left: 20px;
        
        li {
          margin-bottom: 4px;
          font-size: 13px;
          line-height: 1.4;
        }
      }
    }
  }
  
  :deep(.el-table) {
    .el-input {
      .el-input__wrapper {
        box-shadow: 0 0 0 1px var(--el-border-color) inset;
      }
    }
  }
}

// 响应式设计
@media (max-width: 768px) {
  .system-configs-container {
    :deep(.el-table) {
      font-size: 12px;
      
      .el-table__cell {
        padding: 8px 4px;
      }
      
      .el-button {
        font-size: 12px;
        padding: 4px 6px;
      }
    }

    .operation-actions {
      flex-direction: column;
      gap: 2px;
    }
    
    .config-hints {
      :deep(.el-alert__content) {
        ul li {
          font-size: 12px;
        }
      }
    }
  }
}

@media (max-width: 480px) {
  .system-configs-container {
    :deep(.el-table) {
      .el-table__cell {
        padding: 6px 2px;
      }
    }
  }
}
</style>

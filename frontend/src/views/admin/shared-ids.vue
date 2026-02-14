<template>
  <div class="admin-page admin-shared-ids">
    <div class="page-header">
      <h2>苹果账号管理</h2>
      <p>统一管理共享 Apple ID 配置</p>
    </div>

    <VxeTableBar
      :vxeTableRef="vxeTableRef"
      :columns="columns"
      title="苹果账号列表"
      @refresh="fetchList"
    >
      <template #buttons>
        <el-input
          v-model="filters.keyword"
          placeholder="搜索名称或拉取地址"
          clearable
          @clear="handleSearch"
          @keyup.enter="handleSearch"
          style="width: 220px; margin-right: 12px;"
        >
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select
          v-model="filters.status"
          placeholder="状态"
          clearable
          style="width: 150px; margin-right: 12px;"
          @change="handleSearch"
        >
          <el-option label="全部状态" value="" />
          <el-option label="启用" value="1" />
          <el-option label="禁用" value="0" />
        </el-select>
        <el-button type="primary" @click="openCreate"><el-icon><Plus /></el-icon>新增苹果账号</el-button>
      </template>

      <template v-slot="{ size, dynamicColumns }">
        <vxe-grid
          ref="vxeTableRef"
          v-loading="loading"
          show-overflow
          :height="getTableHeight(size)"
          :size="size"
          :column-config="{ resizable: true }"
          :row-config="{ isHover: true, keyField: 'id' }"
          :columns="dynamicColumns"
          :data="records"
          :pager-config="pagerConfig"
          @page-change="handlePageChange"
        >
          <template #name="{ row }">
            <span class="name-text">{{ row.name || '-' }}</span>
          </template>
          <template #fetch_url="{ row }">
            <el-link v-if="row.fetch_url" :href="row.fetch_url" type="primary" target="_blank">
              {{ row.fetch_url }}
            </el-link>
            <span v-else>-</span>
          </template>
          <template #status="{ row }">
            <el-tag :type="row.status === 1 ? 'success' : 'info'" size="small">
              {{ row.status === 1 ? '启用' : '禁用' }}
            </el-tag>
          </template>
          <template #remote_ids="{ row }">
            <span>{{ formatRemoteAccountId(row.remote_account_id) }}</span>
          </template>
          <template #updated_at="{ row }"><span>{{ formatTime(row.updated_at) }}</span></template>
          <template #actions="{ row }">
            <div class="table-actions">
              <el-button size="small" @click="openEdit(row)">编辑</el-button>
              <el-button size="small" type="danger" @click="handleDelete(row)">删除</el-button>
            </div>
          </template>
        </vxe-grid>
      </template>
    </VxeTableBar>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="540px" destroy-on-close>
      <el-form ref="formRef" :model="form" :rules="rules" label-width="110px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="展示给用户的名称" maxlength="40" show-word-limit />
        </el-form-item>
        <el-form-item label="拉取 URL" prop="fetch_url">
          <el-input v-model="form.fetch_url" placeholder="https://example.com/accounts.json" />
        </el-form-item>
        <el-form-item label="远程账号 ID" prop="remote_account_id">
          <el-input
            v-model="form.remote_account_id"
            placeholder="示例：53 或 [53,56,55]"
            clearable
          />
          <div class="form-help">
            支持填写单个数字 ID，或 JSON 数组（也兼容逗号分隔，如：53,56,55）。
          </div>
        </el-form-item>
        <el-form-item label="状态">
          <el-switch v-model="form.status" :active-value="1" :inactive-value="0" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="handleSubmit">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, computed, onMounted } from "vue";
import { ElMessage, ElMessageBox, type FormInstance, type FormRules } from "element-plus";
import { Search, Plus } from "@element-plus/icons-vue";
import { VxeTableBar } from "@/components/ReVxeTableBar";
import {
  getSharedIdConfigs,
  createSharedIdConfig,
  updateSharedIdConfig,
  deleteSharedIdConfig,
  type SharedIdConfig,
} from "@/api/admin";

const vxeTableRef = ref();
const loading = ref(false);
const saving = ref(false);
const records = ref<SharedIdConfig[]>([]);
const pagerConfig = reactive<VxePagerConfig>({
  total: 0,
  currentPage: 1,
  pageSize: 20,
  pageSizes: [10, 20, 50, 100],
  layouts: ['Total', 'Sizes', 'PrevPage', 'Number', 'NextPage', 'FullJump']
});

const filters = reactive({
  keyword: "",
  status: "",
});

const getTableHeight = computed(() => (size: string) => {
  switch (size) {
    case 'medium': return 600;
    case 'small': return 550;
    case 'mini': return 500;
    default: return 600;
  }
});

const columns: VxeTableBarColumns = [
  { field: 'id', title: 'ID', width: 80, visible: true },
  { field: 'name', title: '名称', minWidth: 180, visible: true, slots: { default: 'name' } },
  { field: 'fetch_url', title: '拉取地址', minWidth: 260, visible: true, slots: { default: 'fetch_url' } },
  { field: 'remote_account_id', title: '远程ID', width: 160, visible: true, slots: { default: 'remote_ids' } },
  { field: 'status', title: '状态', width: 120, visible: true, slots: { default: 'status' } },
  { field: 'updated_at', title: '更新时间', width: 180, visible: true, slots: { default: 'updated_at' } },
  { field: 'actions', title: '操作', width: 200, fixed: 'right', visible: true, slots: { default: 'actions' }, columnSelectable: false }
];

const dialogVisible = ref(false);
const isEdit = ref(false);
const formRef = ref<FormInstance>();
const form = reactive({
  id: 0,
  name: "",
  fetch_url: "",
  remote_account_id: "1",
  status: 1,
});

const parseRemoteAccountIdInput = (raw: unknown): number | number[] => {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value) {
    throw new Error("请输入远程 ID");
  }

  if (/^\d+$/.test(value)) {
    const num = Number(value);
    if (!Number.isSafeInteger(num) || num <= 0) {
      throw new Error("远程 ID 需大于 0");
    }
    return num;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed === "number") {
      if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new Error("远程 ID 需大于 0");
      return parsed;
    }
    if (Array.isArray(parsed)) {
      const ids = parsed
        .map((item) => Number(item))
        .filter((item) => Number.isSafeInteger(item) && item > 0);
      const unique = Array.from(new Set(ids));
      if (unique.length === 0) throw new Error("远程 ID 数组不能为空");
      return unique.length === 1 ? unique[0] : unique;
    }
  } catch {
    // fallthrough to CSV parse
  }

  const ids = value
    .split(/[,，\s]+/g)
    .map((item) => Number(item.trim()))
    .filter((item) => Number.isSafeInteger(item) && item > 0);
  const unique = Array.from(new Set(ids));
  if (unique.length === 0) {
    throw new Error("请输入数字 ID 或 ID 数组");
  }
  return unique.length === 1 ? unique[0] : unique;
};

const formatRemoteAccountId = (value: unknown): string => {
  if (Array.isArray(value)) return value.filter((v) => v !== null && v !== undefined).join(", ");
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "-";
  if (typeof value === "string") return value.trim() || "-";
  return "-";
};

const rules: FormRules = {
  name: [
    { required: true, message: "请输入名称", trigger: "blur" },
    { min: 2, max: 40, message: "名称长度需在2~40个字符之间", trigger: "blur" },
  ],
  fetch_url: [
    { required: true, message: "请输入拉取 URL", trigger: "blur" },
    {
      validator: (_rule, value, callback) => {
        if (!value) {
          callback(new Error("请输入拉取 URL"));
          return;
        }
        try {
          new URL(value);
          callback();
        } catch {
          callback(new Error("URL 格式不正确"));
        }
      },
      trigger: "blur",
    },
  ],
  remote_account_id: [
    { required: true, message: "请输入远程 ID", trigger: "blur" },
    {
      validator: (_rule, value, callback) => {
        try {
          parseRemoteAccountIdInput(value);
          callback();
        } catch (error) {
          const message = error instanceof Error ? error.message : "远程 ID 格式不正确";
          callback(new Error(message));
        }
      },
      trigger: "blur",
    },
  ],
};

const dialogTitle = computed(() => (isEdit.value ? "编辑苹果账号" : "新增苹果账号"));

const fetchList = async () => {
  loading.value = true;
  try {
    const { data } = await getSharedIdConfigs({
      page: pagerConfig.currentPage,
      limit: pagerConfig.pageSize,
      keyword: filters.keyword || undefined,
      status: filters.status === "" ? undefined : Number(filters.status),
    });
    records.value = data?.records ?? [];
    pagerConfig.total = data?.pagination?.total ?? 0;
    pagerConfig.currentPage = data?.pagination?.page ?? pagerConfig.currentPage;
    pagerConfig.pageSize = data?.pagination?.limit ?? pagerConfig.pageSize;
  } catch (error) {
    console.error(error);
    ElMessage.error("获取苹果账号失败");
  } finally {
    loading.value = false;
  }
};

const handleSearch = () => {
  pagerConfig.currentPage = 1;
  fetchList();
};

const handlePageChange = ({ currentPage, pageSize }) => {
  pagerConfig.currentPage = currentPage;
  pagerConfig.pageSize = pageSize;
  fetchList();
};

const openCreate = () => {
  isEdit.value = false;
  Object.assign(form, {
    id: 0,
    name: "",
    fetch_url: "",
    remote_account_id: "1",
    status: 1,
  });
  dialogVisible.value = true;
};

const openEdit = (record: SharedIdConfig) => {
  isEdit.value = true;
  Object.assign(form, {
    ...record,
    remote_account_id: Array.isArray(record.remote_account_id)
      ? JSON.stringify(record.remote_account_id)
      : String(record.remote_account_id ?? ""),
  });
  dialogVisible.value = true;
};

const handleSubmit = async () => {
  const formInstance = formRef.value;
  if (!formInstance) return;
  await formInstance.validate();

  saving.value = true;
  try {
    const remoteAccountId = parseRemoteAccountIdInput(form.remote_account_id);
    const payload = {
      name: form.name,
      fetch_url: form.fetch_url,
      remote_account_id: remoteAccountId,
      status: form.status,
    };
    if (isEdit.value && form.id) {
      await updateSharedIdConfig(form.id, payload);
      ElMessage.success("更新成功");
    } else {
      await createSharedIdConfig(payload);
      ElMessage.success("创建成功");
    }
    dialogVisible.value = false;
    fetchList();
  } catch (error) {
    console.error(error);
    ElMessage.error("保存失败");
  } finally {
    saving.value = false;
  }
};

const handleDelete = async (record: SharedIdConfig) => {
  try {
    await ElMessageBox.confirm(`确定删除苹果账号【${record.name}】吗？`, "提示", { type: "warning" });
    await deleteSharedIdConfig(record.id);
    ElMessage.success("删除成功");
    fetchList();
  } catch (error) {
    if (error === "cancel" || error === "close") return;
    console.error(error);
    ElMessage.error("删除失败");
  }
};

const formatTime = (time?: string) => {
  if (!time) return "-";
  const date = new Date(time);
  return Number.isNaN(date.getTime()) ? time : date.toLocaleString();
};

onMounted(fetchList);
</script>

<style scoped lang="scss">
.admin-shared-ids {
  .page-header {
    margin-bottom: 16px;
    h2 { margin: 0 0 8px 0; color: #303133; font-size: 24px; }
    p { margin: 0; color: #909399; }
  }

  .apple-name {
    display: flex;
    align-items: center;
    gap: 10px;

    .name-text {
      font-weight: 500;
      color: #303133;
    }
  }

  .table-actions {
    display: flex;
    gap: 8px;
  }

  .form-help {
    margin-top: 6px;
    font-size: 12px;
    color: #909399;
    line-height: 1.4;
  }
}
</style>

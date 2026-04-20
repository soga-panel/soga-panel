<template>
  <div class="announcements-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">📢 公告详情</h1>
    </div>

    <!-- 公告列表 -->
    <div class="announcements-container">
      <div v-if="loading" class="loading-container">
        <el-skeleton :rows="3" animated />
      </div>

      <div v-else-if="error" class="error-container">
        <el-alert
          title="加载失败"
          :description="error"
          type="error"
          :closable="false"
          center
        />
        <el-button @click="loadAnnouncements" type="primary" style="margin-top: 16px;">
          重试
        </el-button>
      </div>

      <div v-else-if="announcements.length === 0" class="empty-container">
        <el-empty description="暂无公告">
          <el-button @click="loadAnnouncements" type="primary">刷新</el-button>
        </el-empty>
      </div>

      <div v-else class="announcements-list">
        <div
          v-for="announcement in announcements"
          :key="announcement.id"
          class="announcement-item"
          :class="`announcement-type-${announcement.type}`"
        >
          <!-- 公告头部 -->
          <div class="announcement-header">
            <div class="announcement-title-section">
              <span class="announcement-icon">
                <el-icon v-if="announcement.type === 'info'"><InfoFilled /></el-icon>
                <el-icon v-else-if="announcement.type === 'warning'"><WarningFilled /></el-icon>
                <el-icon v-else-if="announcement.type === 'success'"><SuccessFilled /></el-icon>
                <el-icon v-else-if="announcement.type === 'danger'"><CircleCloseFilled /></el-icon>
                <el-icon v-else><Bell /></el-icon>
              </span>
              <h2 class="announcement-title">{{ announcement.title }}</h2>
              <el-tag
                v-if="announcement.is_pinned"
                type="warning"
                size="small"
                class="pinned-tag"
              >
                置顶
              </el-tag>
            </div>
            <div class="announcement-meta">
              <span class="announcement-time">
                <el-icon><Clock /></el-icon>
                {{ formatTime(announcement.created_at) }}
              </span>
            </div>
          </div>

          <!-- 公告内容 -->
          <div class="announcement-content">
            <div
              class="content-text markdown-content"
              v-html="renderAnnouncementContent(announcement)"
            ></div>
          </div>

          <!-- 公告底部信息 -->
          <div class="announcement-footer">
            <div class="announcement-info">
              <span v-if="announcement.created_by_name" class="author">
                发布者: {{ announcement.created_by_name }}
              </span>
              <span v-if="announcement.expires_at && !announcement.is_expired" class="expires">
                有效期至: {{ formatTime(announcement.expires_at) }}
              </span>
              <span v-if="announcement.is_expired" class="expired-tag">
                <el-tag type="info" size="small">已过期</el-tag>
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- 加载更多 -->
      <div v-if="hasMore && !loading" class="load-more">
        <el-button @click="loadMore" :loading="loadingMore" type="primary" plain>
          加载更多
        </el-button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import {
  InfoFilled,
  WarningFilled,
  SuccessFilled,
  CircleCloseFilled,
  Bell,
  Clock
} from '@element-plus/icons-vue';
import { getAnnouncements, type Announcement } from '@/api/announcement';
import { renderMarkdown } from '@/utils/markdown';

// 响应式数据
const announcements = ref<Announcement[]>([]);
const loading = ref(false);
const loadingMore = ref(false);
const error = ref('');
const hasMore = ref(true);
const offset = ref(0);
const limit = 10;

const getAnnouncementSortKey = (announcement: Announcement): number => {
  const rawCreatedAt = (announcement as { created_at?: unknown }).created_at;
  if (typeof rawCreatedAt === "number" && Number.isFinite(rawCreatedAt)) {
    return rawCreatedAt;
  }

  const numericValue = Number(rawCreatedAt);
  if (Number.isFinite(numericValue)) {
    return numericValue;
  }

  if (typeof rawCreatedAt === "string") {
    const parsedMs = Date.parse(rawCreatedAt);
    if (Number.isFinite(parsedMs)) {
      return Math.floor(parsedMs / 1000);
    }
  }

  return 0;
};

const sortAnnouncementsByLatest = (items: Announcement[]): Announcement[] => {
  return [...items].sort((a, b) => {
    const createdAtDiff = getAnnouncementSortKey(b) - getAnnouncementSortKey(a);
    if (createdAtDiff !== 0) {
      return createdAtDiff;
    }
    return b.id - a.id;
  });
};

const renderAnnouncementContent = (announcement: Announcement): string => {
  const markdown = (announcement.content || '').trim();
  if (markdown) {
    return renderMarkdown(markdown);
  }
  return announcement.content_html || '';
};

// 加载公告列表
const loadAnnouncements = async (isLoadMore = false) => {
  if (isLoadMore) {
    loadingMore.value = true;
  } else {
    loading.value = true;
    offset.value = 0;
    announcements.value = [];
  }

  error.value = '';

  try {
    const { data } = await getAnnouncements({
      limit,
      offset: offset.value
    });

    // 过滤掉置顶公告，只显示非置顶公告
    const filteredData = data.filter((announcement: Announcement) => !announcement.is_pinned);

    if (isLoadMore) {
      announcements.value = sortAnnouncementsByLatest([
        ...announcements.value,
        ...filteredData
      ]);
    } else {
      announcements.value = sortAnnouncementsByLatest(filteredData);
    }

    // 如果返回的数据少于限制数量，说明没有更多了
    hasMore.value = data.length === limit;
    offset.value += data.length;

  } catch (err: any) {
    error.value = err.message || '加载公告失败';
    ElMessage.error(error.value);
  } finally {
    loading.value = false;
    loadingMore.value = false;
  }
};

// 加载更多
const loadMore = () => {
  loadAnnouncements(true);
};

// 格式化时间
const formatTime = (timestamp: number): string => {
  const date = new Date(timestamp * 1000);
  const now = new Date();
  const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));

  if (diffInHours < 1) {
    const diffInMinutes = Math.floor((now.getTime() - date.getTime()) / (1000 * 60));
    return diffInMinutes < 1 ? '刚刚' : `${diffInMinutes}分钟前`;
  }

  if (diffInHours < 24) {
    return `${diffInHours}小时前`;
  }

  if (diffInHours < 168) { // 7天
    return `${Math.floor(diffInHours / 24)}天前`;
  }

  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  });
};

// 页面加载时获取公告
onMounted(() => {
  loadAnnouncements();
});
</script>

<style scoped lang="scss">
.announcements-page {
  padding: 24px;
  background: #f5f7fa;
  min-height: 100%;
  width: 100%;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  box-sizing: border-box;

  .page-header {
    margin: 0 auto 24px;
    width: 100%;
    max-width: 1200px;


    .page-title {
      font-size: 28px;
      font-weight: 600;
      color: #303133;
      margin: 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }
  }

  .announcements-container {
    width: 100%;
    max-width: 1200px;
    margin: 0 auto;
    box-sizing: border-box;

    .loading-container,
    .error-container,
    .empty-container {
      background: white;
      border-radius: 8px;
      padding: 40px;
      text-align: center;
      box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
    }

    .announcements-list {
      .announcement-item {
        background: white;
        border-radius: 8px;
        margin: 0 auto 16px;
        padding: 16px;
        box-shadow: 0 2px 8px 0 rgba(0, 0, 0, 0.1);
        border-left: 3px solid transparent;
        transition: all 0.3s ease;
        width: 100%;
        box-sizing: border-box;

        &:hover {
          box-shadow: 0 4px 20px 0 rgba(0, 0, 0, 0.15);
          transform: translateY(-2px);
        }

        &.announcement-type-info {
          border-left-color: #409eff;

          .announcement-icon {
            color: #409eff;
            background-color: rgba(64, 158, 255, 0.1);
          }
        }

        &.announcement-type-warning {
          border-left-color: #e6a23c;

          .announcement-icon {
            color: #e6a23c;
            background-color: rgba(230, 162, 60, 0.1);
          }
        }

        &.announcement-type-success {
          border-left-color: #67c23a;

          .announcement-icon {
            color: #67c23a;
            background-color: rgba(103, 194, 58, 0.1);
          }
        }

        &.announcement-type-danger {
          border-left-color: #f56c6c;

          .announcement-icon {
            color: #f56c6c;
            background-color: rgba(245, 108, 108, 0.1);
          }
        }

        .announcement-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 12px;

          .announcement-title-section {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;

            .announcement-icon {
              width: 32px;
              height: 32px;
              border-radius: 50%;
              display: flex;
              align-items: center;
              justify-content: center;
              font-size: 16px;
              flex-shrink: 0;
            }

            .announcement-title {
              font-size: 18px;
              font-weight: 600;
              color: #303133;
              margin: 0;
              line-height: 1.4;
              flex: 1;
            }

            .pinned-tag {
              flex-shrink: 0;
            }
          }

          .announcement-meta {
            .announcement-time {
              display: flex;
              align-items: center;
              gap: 4px;
              color: #909399;
              font-size: 14px;
              white-space: nowrap;

              .el-icon {
                font-size: 16px;
              }
            }
          }
        }

        .announcement-content {
          margin-bottom: 12px;

          .content-text {
            color: #606266;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-break: break-word;
          }

          :deep(p) {
            margin: 0 0 8px 0;
            color: #606266;
            font-size: 14px;
            line-height: 1.5;

            &:last-child {
              margin-bottom: 0;
            }
          }

          :deep(h1), :deep(h2), :deep(h3), :deep(h4), :deep(h5), :deep(h6) {
            color: #303133;
            margin: 12px 0 6px 0;

            &:first-child {
              margin-top: 0;
            }
          }

          :deep(ul), :deep(ol) {
            margin: 12px 0;
            padding-left: 24px;
            color: #606266;
          }

          :deep(code) {
            background-color: #f1f2f3;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 14px;
            color: #e74c3c;
          }

          :deep(pre) {
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 16px;
            margin: 16px 0;
            overflow-x: auto;

            code {
              background: none;
              padding: 0;
              color: #495057;
            }
          }

          :deep(blockquote) {
            margin: 12px 0;
            padding: 8px 12px;
            border-left: 4px solid #dcdfe6;
            background-color: #f8f9fa;
            color: #606266;
          }

          :deep(hr) {
            margin: 16px 0;
            border: 0;
            border-top: 1px solid #e4e7ed;
          }
        }

        .announcement-footer {
          .announcement-info {
            display: flex;
            align-items: center;
            gap: 16px;
            flex-wrap: wrap;

            .author, .expires {
              font-size: 14px;
              color: #909399;
            }

            .author {
              font-weight: 500;
            }

            .expires {
              font-style: italic;
            }
          }
        }
      }
    }

    .load-more {
      text-align: center;
      padding: 20px;
    }
  }
}

// 响应式设计
@media (max-width: 768px) {
  .announcements-page {
    padding: 16px;
    min-height: calc(100vh - 100px);

    .page-header {
      margin-bottom: 16px;


      .page-title {
        font-size: 22px;
      }
    }

    .announcements-container {
      .loading-container,
      .error-container,
      .empty-container {
        padding: 30px 16px;
      }

      .announcements-list {
        .announcement-item {
          padding: 16px;
          margin-bottom: 12px;
          border-radius: 6px;

          .announcement-header {
            flex-direction: column;
            align-items: flex-start;
            gap: 8px;
            margin-bottom: 12px;

            .announcement-title-section {
              width: 100%;
              gap: 10px;

              .announcement-icon {
                width: 28px;
                height: 28px;
                font-size: 14px;
              }

              .announcement-title {
                font-size: 16px;
                line-height: 1.3;
              }
            }

            .announcement-meta {
              align-self: flex-start;

              .announcement-time {
                font-size: 13px;
              }
            }
          }

          .announcement-content {
            margin-bottom: 10px;

            .content-text {
              font-size: 14px;
              line-height: 1.6;
            }

            :deep(p) {
              font-size: 14px;
              line-height: 1.6;
            }
          }

          .announcement-footer {
            .announcement-info {
              gap: 12px;

              .author,
              .expires {
                font-size: 13px;
              }
            }
          }
        }
      }

      .load-more {
        padding: 16px;
      }
    }
  }
}

@media (max-width: 480px) {
  .announcements-page {
    padding: 12px;

    .page-header {
      .page-title {
        font-size: 20px;
      }
    }

    .announcements-container {
      .announcements-list {
        .announcement-item {
          padding: 12px;

          .announcement-header {
            .announcement-title-section {
              gap: 8px;

              .announcement-icon {
                width: 24px;
                height: 24px;
                font-size: 13px;
              }

              .announcement-title {
                font-size: 15px;
              }
            }

            .announcement-meta {
              .announcement-time {
                font-size: 12px;
              }
            }
          }

          .announcement-content {
            .content-text {
              font-size: 13px;
            }

            :deep(p) {
              font-size: 13px;
            }
          }

          .announcement-footer {
            .announcement-info {
              .author,
              .expires {
                font-size: 12px;
              }
            }
          }
        }
      }
    }
  }
}
</style>

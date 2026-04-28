import { ElMessage, ElMessageBox } from 'element-plus';

export interface ErrorInfo {
  code?: string;
  message: string;
  stack?: string;
  timestamp: Date;
}

class ErrorHandler {
  private errorLog: ErrorInfo[] = [];
  private maxLogSize = 100;

  private normalizeUnknownErrorMessage(reason: unknown): string {
    if (reason instanceof Error) {
      return reason.message || reason.name || "未知错误";
    }
    if (typeof reason === "string") {
      return reason;
    }
    if (typeof reason === "number" || typeof reason === "boolean") {
      return String(reason);
    }
    if (reason && typeof reason === "object") {
      const maybeMessage = (reason as any).message;
      if (typeof maybeMessage === "string" && maybeMessage.trim()) {
        return maybeMessage;
      }
      const maybeName = (reason as any).name;
      if (typeof maybeName === "string" && maybeName.trim()) {
        return maybeName;
      }
      try {
        return JSON.stringify(reason);
      } catch {
        return "未知错误对象";
      }
    }
    return "未知错误";
  }

  private shouldIgnoreUnhandledRejection(reason: unknown): boolean {
    const message = this.normalizeUnknownErrorMessage(reason).toLowerCase();
    const knownIgnorePatterns = [
      "cancel",
      "canceled",
      "cancelled",
      "aborterror",
      "aborted",
      "navigation cancelled",
      "navigation aborted",
      "avoided redundant navigation",
      "navigationduplicated",
      "user denied",
      "the user aborted a request",
      "the operation was aborted"
    ];

    return knownIgnorePatterns.some((pattern) => message.includes(pattern));
  }

  private isAxiosLikeRejection(reason: unknown): boolean {
    if (!reason || typeof reason !== "object") return false;
    const anyReason = reason as any;
    return (
      anyReason.isAxiosError === true ||
      anyReason.name === "AxiosError"
    );
  }

  private shouldShowUnhandledRejectionToast(reason: unknown): boolean {
    if (this.shouldIgnoreUnhandledRejection(reason)) {
      return false;
    }
    if (this.isAxiosLikeRejection(reason)) {
      // Axios 错误一般已经被业务层或拦截器提示过，避免重复弹窗
      return false;
    }
    if (reason instanceof Error) {
      return true;
    }
    if (typeof reason === "string") {
      return reason.trim().length > 0;
    }
    // 非 Error/字符串（例如路由导航失败对象）通常是可预期拒绝
    return false;
  }

  // 处理API错误
  handleApiError(error: import('axios').AxiosError | Error, context?: string): void {
    const isAxiosError = 'response' in error && error.response;
    const axiosError = error as import('axios').AxiosError;

    const responseData = isAxiosError ? (axiosError.response?.data as any) : undefined;
    const serverMessage = responseData && typeof responseData === 'object' ? responseData.message : undefined;
    const fallbackMessage = '请求失败，请稍后重试';
    const derivedMessage = serverMessage || (!isAxiosError ? error.message : '') || fallbackMessage;

    const errorInfo: ErrorInfo = {
      code: isAxiosError ? axiosError.code : (error as any).code,
      message: derivedMessage,
      stack: error.stack,
      timestamp: new Date()
    };

    // 如果提供了上下文，添加到错误信息中
    if (context) {
      errorInfo.message = `${context}: ${errorInfo.message}`;
    }

    this.logError(errorInfo);

    // 根据错误类型显示不同的消息
    if (isAxiosError) {
      const status = axiosError.response?.status;
      if (serverMessage) {
        ElMessage.error(serverMessage);
        return;
      }
      if (status === 403) {
        ElMessage.error('权限不足，无法访问该资源');
      } else if (status === 404) {
        ElMessage.error('请求的资源不存在');
      } else if (status && status >= 500) {
        ElMessage.error('服务器内部错误，请稍后重试');
      } else {
        ElMessage.error(errorInfo.message || fallbackMessage);
      }
    } else {
      // 处理普通Error对象
      const errorCode = (error as any).code;
      if (errorCode === 'NETWORK_ERROR') {
        ElMessage.error('网络连接失败，请检查网络设置');
      } else if (errorCode === 'TIMEOUT_ERROR') {
        ElMessage.warning('请求超时，请稍后重试');
      } else {
        ElMessage.error(errorInfo.message);
      }
    }
  }

  // 处理组件错误
  handleComponentError(error: Error, instance: unknown, info: string): void {
    const errorInfo: ErrorInfo = {
      message: `组件错误: ${error.message}`,
      stack: error.stack,
      timestamp: new Date()
    };

    this.logError(errorInfo);
    console.error('Component Error:', error, instance, info);

    // 在开发环境中显示详细错误
    if (import.meta.env.DEV) {
      ElMessageBox.alert(
        `组件渲染出现错误: ${error.message}`,
        '开发调试',
        {
          confirmButtonText: '确定',
          type: 'error'
        }
      );
    } else {
      ElMessage.error('页面加载出现问题，请刷新重试');
    }
  }

  // 处理未捕获的错误
  handleUnhandledError(event: ErrorEvent): void {
    // 过滤 ResizeObserver 的常见警告
    if (event.message.includes('ResizeObserver loop completed with undelivered notifications')) {
      // 这是一个常见的浏览器警告，不需要显示给用户
      console.warn('ResizeObserver warning (filtered):', event.message);
      return;
    }

    const errorInfo: ErrorInfo = {
      message: event.message,
      stack: event.error?.stack,
      timestamp: new Date()
    };

    this.logError(errorInfo);
    ElMessage.error('系统出现未预期的错误');
  }

  // 处理未处理的Promise拒绝
  handleUnhandledRejection(event: PromiseRejectionEvent): void {
    if (!this.shouldShowUnhandledRejectionToast(event.reason)) {
      event.preventDefault();
      if (import.meta.env.DEV) {
        console.warn("Ignored unhandled Promise rejection:", event.reason);
      }
      return;
    }

    const reasonText = this.normalizeUnknownErrorMessage(event.reason);
    const errorInfo: ErrorInfo = {
      message: `未处理的Promise拒绝: ${reasonText}`,
      timestamp: new Date()
    };

    this.logError(errorInfo);

    // 阻止浏览器默认输出，避免重复噪音
    event.preventDefault();

    if (import.meta.env.DEV) {
      console.error("Unhandled Promise rejection reason:", event.reason);
    }

    ElMessage.error('系统出现未处理的异步错误');
  }

  // 记录错误
  private logError(errorInfo: ErrorInfo): void {
    // 过滤 ResizeObserver 相关的错误
    if (errorInfo.message.includes('ResizeObserver loop completed with undelivered notifications')) {
      return;
    }

    this.errorLog.unshift(errorInfo);

    // 限制日志大小
    if (this.errorLog.length > this.maxLogSize) {
      this.errorLog = this.errorLog.slice(0, this.maxLogSize);
    }

    // 在开发环境中打印错误
    if (import.meta.env.DEV) {
      console.error('Error logged:', errorInfo);
    }
  }

  // 获取错误日志
  getErrorLog(): ErrorInfo[] {
    return [...this.errorLog];
  }

  // 清空错误日志
  clearErrorLog(): void {
    this.errorLog = [];
  }

  // 导出错误日志
  exportErrorLog(): string {
    return JSON.stringify(this.errorLog, null, 2);
  }
}

// 全局错误处理器实例
export const globalErrorHandler = new ErrorHandler();

// 安装全局错误处理
export function installGlobalErrorHandler() {
  // 处理 ResizeObserver 错误 - 优先处理，阻止进一步传播
  const resizeObserverErrorHandler = (e: ErrorEvent) => {
    if (e.message && e.message.includes('ResizeObserver loop completed with undelivered notifications')) {
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();
      return false;
    }
    return true;
  };

  // 先注册 ResizeObserver 错误处理器 (capture phase)
  window.addEventListener('error', resizeObserverErrorHandler, true);

  // 处理其他未捕获的JavaScript错误
  window.addEventListener('error', (event) => {
    // 如果是 ResizeObserver 错误，跳过处理
    if (event.message && event.message.includes('ResizeObserver loop completed with undelivered notifications')) {
      return;
    }
    globalErrorHandler.handleUnhandledError(event);
  });

  // 处理未处理的Promise拒绝
  window.addEventListener('unhandledrejection', (event) => {
    globalErrorHandler.handleUnhandledRejection(event);
  });
}

// 工具函数：创建带重试的异步函数
export function withRetry<T extends any[], R>(
  fn: (...args: T) => Promise<R>,
  maxRetries = 3,
  delay = 1000
) {
  return async (...args: T): Promise<R> => {
    let lastError: any;
    
    for (let i = 0; i <= maxRetries; i++) {
      try {
        return await fn(...args);
      } catch (error) {
        lastError = error;
        
        if (i === maxRetries) {
          break;
        }
        
        // 等待一段时间后重试
        await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
      }
    }
    
    throw lastError;
  };
}

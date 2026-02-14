export const parseRemoteAccountIdList = (value: unknown): number[] => {
  const normalize = (list: number[]): number[] => {
    const result: number[] = [];
    const seen = new Set<number>();
    for (const item of list) {
      const num = Number(item);
      if (!Number.isSafeInteger(num) || num <= 0) continue;
      if (seen.has(num)) continue;
      seen.add(num);
      result.push(num);
    }
    return result;
  };

  if (typeof value === "number") {
    return normalize([value]);
  }

  if (Array.isArray(value)) {
    return normalize(value.map((item) => Number(item)));
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return [];

    if (/^\d+$/.test(trimmed)) {
      return normalize([Number(trimmed)]);
    }

    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (typeof parsed === "number") {
        return normalize([parsed]);
      }
      if (Array.isArray(parsed)) {
        return normalize(parsed.map((item) => Number(item)));
      }
    } catch {
      // ignore JSON parse errors and fallback to CSV parsing
    }

    return normalize(
      trimmed
        .split(/[,，\s]+/g)
        .filter(Boolean)
        .map((item) => Number(item.trim()))
    );
  }

  return [];
};

export const formatRemoteAccountIdForResponse = (value: unknown): number | number[] => {
  const ids = parseRemoteAccountIdList(value);
  if (ids.length === 0) return 0;
  return ids.length === 1 ? ids[0] : ids;
};

export const serializeRemoteAccountIdForDb = (value: unknown): string => {
  const ids = parseRemoteAccountIdList(value);
  if (ids.length === 0) {
    throw new Error("远程账号 ID 不能为空");
  }
  return ids.length === 1 ? String(ids[0]) : JSON.stringify(ids);
};

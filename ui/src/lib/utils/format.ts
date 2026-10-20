import type { Permission } from '$lib/types/admin';

/**
 * Parses an unsigned 64-bit integer from a decimal string, safe integer, or bigint.
 * @param value - Raw wire value.
 * @returns Parsed bigint, or null when invalid or out of u64 range.
 */
export const decimalU64 = (
	value: string | number | bigint | null | undefined
): bigint | null => {
	if (value === null || value === undefined) return null;
	if (typeof value === 'number' && (Number.isSafeInteger(value) === false || value < 0))
		return null;
	if (typeof value === 'string' && /^\d+$/.test(value) === false) return null;
	const parsed = BigInt(value);
	return parsed >= 0n && parsed <= 18446744073709551615n ? parsed : null;
};

/**
 * Formats an unsigned counter using locale digit grouping without losing u64 precision.
 * @param value - Raw counter value.
 * @returns Formatted counter string.
 */
export const formatCounter = (
	value: string | number | bigint | null | undefined
): string => {
	const exact = decimalU64(value);
	return exact === null ? 'Unavailable' : exact.toLocaleString();
};

/**
 * Formats a byte count into human-readable IEC units using exact bigint arithmetic.
 * @param bytes - Raw byte count.
 * @returns Formatted byte string (for example `4.9 GiB`).
 */
export const formatBytes = (
	bytes: string | number | bigint | null | undefined
): string => {
	const exact = decimalU64(bytes);
	if (exact === null) return 'Unavailable';
	const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
	let unitIndex = 0;
	let divisor = 1n;
	while (exact >= divisor * 1024n && unitIndex < units.length - 1) {
		divisor *= 1024n;
		unitIndex += 1;
	}
	if (unitIndex === 0) return `${exact.toLocaleString()} B`;
	const tenths = (exact * 10n + divisor / 2n) / divisor;
	return `${tenths / 10n}.${tenths % 10n} ${units[unitIndex]}`;
};

/**
 * Computes a bounded percentage (0 to 100) between two u64 byte values.
 * @param used - Numerator byte value.
 * @param limit - Denominator ceiling byte value.
 * @returns Percentage between 0 and 100.
 */
export const formatPercent = (
	used: string | number | bigint | null | undefined,
	limit: string | number | bigint | null | undefined
): number => {
	const usedVal = decimalU64(used);
	const limitVal = decimalU64(limit);
	if (usedVal === null || limitVal === null || limitVal <= 0n) return 0;
	const basisPoints = Number((usedVal * 10000n) / limitVal);
	return Math.min(100, Math.max(0, Math.round(basisPoints / 100)));
};

/**
 * Formats a duration in seconds into a compact age or lease string.
 * @param seconds - Duration in seconds, or null.
 * @returns Formatted duration string.
 */
export const formatDuration = (seconds: number | null): string => {
	if (seconds === null) return 'None';
	if (seconds < 60) return `${seconds}s`;
	if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
	const hours = Math.floor(seconds / 3600);
	const minutes = Math.floor((seconds % 3600) / 60);
	return `${hours}h ${minutes}m`;
};

/**
 * Formats a Unix epoch timestamp (seconds) into a local date-time string.
 * @param timestamp - Unix timestamp in seconds, or null.
 * @returns Formatted date string.
 */
export const formatTimestamp = (timestamp: number | null): string => {
	if (timestamp === null || timestamp <= 0) return 'Never';
	return new Date(timestamp * 1000).toLocaleString();
};

/**
 * Returns a human-readable label for a permission identifier.
 * @param permission - Permission enum value.
 * @returns Readable label.
 */
export const formatPermission = (permission: Permission): string => {
	if (permission === 'view_status') return 'View status';
	if (permission === 'trigger_sync') return 'Sync mirrors';
	if (permission === 'manage_cache') return 'Manage cache';
	if (permission === 'manage_users') return 'Manage users';
	if (permission === 'view_inventory') return 'View inventory';
	if (permission === 'view_audit') return 'View audit history';
	if (permission === 'manage_config') return 'Manage configuration';
	return 'Acknowledge alerts';
};

from datetime import datetime, timezone

def parse_timestamp(timestamp_str: str) -> datetime:
    """Parse an ISO 8601 timestamp string to a timezone-aware datetime object."""
    try:
        # Handle timestamps that might already have 'Z' or an offset
        if 'Z' in timestamp_str.upper():
            dt = datetime.fromisoformat(timestamp_str.upper().replace('Z', '+00:00'))
        elif '+' in timestamp_str or '-' in timestamp_str[10:]: # Check for offset beyond date part
            dt = datetime.fromisoformat(timestamp_str)
        else:
            # Assume naive timestamp is UTC if no timezone info
            dt_naive = datetime.fromisoformat(timestamp_str)
            dt = dt_naive.replace(tzinfo=timezone.utc)

        # Ensure it's UTC if it has an offset
        if dt.tzinfo is not None and dt.tzinfo != timezone.utc:
            dt = dt.astimezone(timezone.utc)
        elif dt.tzinfo is None: # Should have been caught by above, but as a safeguard
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    except ValueError as e:
        # Fallback for simple YYYY-MM-DDTHH:MM:SS if fromisoformat fails on non-standard parts
        try:
            dt_naive = datetime.strptime(timestamp_str.split('.')[0], "%Y-%m-%dT%H:%M:%S") # Ignore millis for simpler parsing
            return dt_naive.replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError(f"Could not parse timestamp: {timestamp_str}. Original error: {e}")
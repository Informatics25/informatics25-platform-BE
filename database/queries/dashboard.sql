SELECT id, time_start, time_end, activity, location
FROM schedules
WHERE DATE(time_start) = CURRENT_DATE
ORDER BY time_start ASC;

SELECT id, title, content, created_at
FROM announcements
WHERE is_active = TRUE
ORDER BY created_at DESC
    LIMIT 5;
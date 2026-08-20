CREATE TABLE IF NOT EXISTS announcements (
                                             id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

CREATE TABLE IF NOT EXISTS schedules (
                                         id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    time_start TIMESTAMP WITH TIME ZONE NOT NULL,
    time_end TIMESTAMP WITH TIME ZONE NOT NULL,
                           activity VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL
    );
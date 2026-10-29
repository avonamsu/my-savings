-- ============================================================
-- my-savings: Web Push Setup
-- Запусти этот SQL в Supabase Dashboard → SQL Editor
-- ============================================================

-- 1. Таблица push_subscriptions
CREATE TABLE IF NOT EXISTS public.push_subscriptions (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  endpoint   text NOT NULL,
  p256dh     text NOT NULL,
  auth       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, endpoint)
);

-- 2. RLS (Row Level Security)
ALTER TABLE public.push_subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own push subscriptions"
  ON public.push_subscriptions
  FOR ALL
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 3. Cron: запуск Edge Function каждый день в 06:00 UTC (09:00 МСК)
-- Нужно включить расширение pg_cron в Dashboard → Database → Extensions
SELECT cron.schedule(
  'daily-push-notifications',
  '0 6 * * *',
  $$
    SELECT net.http_post(
      url := 'https://lcumgywtiydwbbbvtcld.supabase.co/functions/v1/notify-subscriptions',
      headers := '{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImxjdW1neXd0aXlkd2JiYnZ0Y2xkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5MTc0ODA5NiwiZXhwIjoyMTA3MzI0MDk2fQ.JsNjty6WP5ixvgL13aGZGj0Oej0TMblJZqXRv2IlHpg", "Content-Type": "application/json"}'::jsonb,
      body := '{}'::jsonb
    );
  $$
);

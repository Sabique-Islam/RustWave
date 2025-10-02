-- 1. Add custom users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  
  -- Email verification
  email_verified BOOLEAN DEFAULT false,
  email_verification_token TEXT,
  email_verified_at TIMESTAMPTZ,
  
  -- Account status
  is_active BOOLEAN DEFAULT true,
  
  -- Metadata
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  last_sign_in_at TIMESTAMPTZ,
  
  CONSTRAINT email_format CHECK (email ~ '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
  CONSTRAINT username_format CHECK (username ~ '^[a-zA-Z0-9_]{1,50}$')
);

-- 2. Update profiles table (only change the reference)
-- Change this line:
-- id UUID REFERENCES auth.users(id) PRIMARY KEY,
-- To this:
ALTER TABLE profiles DROP CONSTRAINT profiles_id_fkey;
ALTER TABLE profiles ADD CONSTRAINT profiles_id_fkey FOREIGN KEY (id) REFERENCES users(id);
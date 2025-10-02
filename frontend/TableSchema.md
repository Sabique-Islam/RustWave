-- ============================================================================
-- RustWave - Database Schema
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm"; -- For fuzzy text search
CREATE EXTENSION IF NOT EXISTS "btree_gin"; -- For composite indexes

-- ============================================================================
-- CREATE ALL ENUM TYPES
-- ============================================================================

-- User roles enum
CREATE TYPE user_role AS ENUM (
  'user',
  'moderator', 
  'admin',
  'superadmin'
);

-- User status enum
CREATE TYPE user_status AS ENUM (
  'active',
  'inactive',
  'suspended',
  'banned',
  'pending_verification'
);

-- ActivityPub actor types
CREATE TYPE activitypub_actor_type AS ENUM (
  'Person',
  'Service',
  'Group',
  'Organization',
  'Application'
);

-- Post visibility enum
CREATE TYPE post_visibility AS ENUM (
  'public',
  'unlisted', 
  'followers',
  'direct'
);

-- ActivityPub object types
CREATE TYPE activitypub_object_type AS ENUM (
  'Note',
  'Article',
  'Question',
  'Announce'
);

-- Federation status
CREATE TYPE federation_status AS ENUM (
  'pending',
  'federated',
  'failed',
  'local_only'
);

-- Follow status
CREATE TYPE follow_status AS ENUM ('pending', 'accepted', 'rejected');

-- Block reason
CREATE TYPE block_reason AS ENUM ('spam', 'harassment', 'inappropriate_content', 'other');

-- Storage provider
CREATE TYPE storage_provider AS ENUM ('local', 's3', 'gcs', 'azure', 'supabase');

-- Media type
CREATE TYPE media_type AS ENUM ('image', 'video', 'audio', 'document');

-- Processing status
CREATE TYPE processing_status AS ENUM ('pending', 'processing', 'completed', 'failed');

-- Notification type
CREATE TYPE notification_type AS ENUM (
  'follow',
  'follow_request',
  'mention',
  'reply',
  'reblog',
  'favourite',
  'poll_ended',
  'status_update',
  'system',
  'admin_announcement',
  'moderation_warning'
);

-- Delivery method
CREATE TYPE delivery_method AS ENUM ('in_app', 'email', 'push', 'webhook');

-- Security event type
CREATE TYPE security_event_type AS ENUM (
  'login_success',
  'login_failure',
  'logout',
  'password_change',
  'email_change',
  '2fa_enabled',
  '2fa_disabled',
  'suspicious_login',
  'account_locked',
  'account_unlocked',
  'password_reset_requested',
  'password_reset_completed'
);

-- Theme preference
CREATE TYPE theme_preference AS ENUM ('light', 'dark', 'auto');

-- Report category
CREATE TYPE report_category AS ENUM (
  'spam',
  'harassment',
  'hate_speech',
  'violence',
  'self_harm',
  'sexual_content',
  'misinformation',
  'copyright',
  'impersonation',
  'other'
);

-- Report status
CREATE TYPE report_status AS ENUM ('open', 'investigating', 'resolved', 'dismissed', 'escalated');

-- Report priority
CREATE TYPE report_priority AS ENUM ('low', 'medium', 'high', 'urgent');

-- Moderation action
CREATE TYPE moderation_action AS ENUM (
  'no_action',
  'content_warning_added',
  'post_deleted',
  'user_warned',
  'user_silenced',
  'user_suspended',
  'user_banned'
);

-- ============================================================================
-- 1. USERS TABLE (Authentication & Core Identity)
-- ============================================================================

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- Authentication
  email VARCHAR(320) UNIQUE NOT NULL, -- RFC 5321 max length
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  
  -- Security & Verification
  email_verified BOOLEAN DEFAULT false NOT NULL,
  email_verification_token VARCHAR(255),
  email_verification_expires_at TIMESTAMPTZ,
  password_reset_token VARCHAR(255),
  password_reset_expires_at TIMESTAMPTZ,
  
  -- Access Control
  role user_role DEFAULT 'user' NOT NULL,
  permissions TEXT[] DEFAULT '{}',
  
  -- Account Status
  status user_status DEFAULT 'active' NOT NULL,
  suspended_until TIMESTAMPTZ,
  suspension_reason TEXT,
  failed_login_attempts INTEGER DEFAULT 0 NOT NULL,
  locked_until TIMESTAMPTZ,
  
  -- Security Tracking
  last_password_change TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  require_password_change BOOLEAN DEFAULT false NOT NULL,
  two_factor_enabled BOOLEAN DEFAULT false NOT NULL,
  two_factor_secret TEXT,
  backup_codes TEXT[],
  
  -- Audit Trail
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  last_sign_in_at TIMESTAMPTZ,
  last_sign_in_ip INET,
  current_sign_in_at TIMESTAMPTZ,
  current_sign_in_ip INET,
  sign_in_count INTEGER DEFAULT 0 NOT NULL,
  
  -- Data Retention
  deleted_at TIMESTAMPTZ,
  gdpr_delete_requested_at TIMESTAMPTZ,
  
  -- Constraints
  CONSTRAINT users_email_format CHECK (
    email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
  ),
  CONSTRAINT users_username_format CHECK (
    username ~ '^[a-zA-Z0-9_]{3,50}$'
  ),
  CONSTRAINT users_password_hash_not_empty CHECK (
    length(trim(password_hash)) > 0
  ),
  CONSTRAINT users_valid_suspension CHECK (
    (status = 'suspended' AND suspended_until IS NOT NULL) OR 
    (status != 'suspended')
  )
);

-- Indexes for users table
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email_verification_token ON users(email_verification_token) 
  WHERE email_verification_token IS NOT NULL;
CREATE INDEX idx_users_password_reset_token ON users(password_reset_token) 
  WHERE password_reset_token IS NOT NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_last_sign_in ON users(last_sign_in_at) WHERE deleted_at IS NULL;

-- ============================================================================
-- 2. PROFILES TABLE (Public User Data & ActivityPub)
-- ============================================================================

CREATE TABLE profiles (
  id UUID REFERENCES users(id) PRIMARY KEY,
  
  -- Display Information
  display_name VARCHAR(100),
  bio TEXT,
  pronouns VARCHAR(50),
  location VARCHAR(100),
  website_url TEXT,
  birth_date DATE,
  
  -- Media
  avatar_url TEXT,
  banner_url TEXT,
  avatar_blurhash VARCHAR(100),
  banner_blurhash VARCHAR(100),
  
  -- ActivityPub Identity
  actor_id VARCHAR(500) UNIQUE NOT NULL, -- Increased for long domains
  actor_type activitypub_actor_type DEFAULT 'Person' NOT NULL,
  
  -- Cryptographic Keys
  public_key TEXT NOT NULL,
  private_key_encrypted TEXT NOT NULL,
  key_id VARCHAR(500) NOT NULL,
  
  -- Federation
  is_local BOOLEAN DEFAULT true NOT NULL,
  domain VARCHAR(253), -- RFC 1035 max domain length
  shared_inbox_url TEXT,
  inbox_url TEXT NOT NULL,
  outbox_url TEXT NOT NULL,
  followers_url TEXT,
  following_url TEXT,
  featured_url TEXT,
  
  -- Discovery & Privacy
  is_discoverable BOOLEAN DEFAULT true NOT NULL,
  is_indexable BOOLEAN DEFAULT true NOT NULL,
  is_locked BOOLEAN DEFAULT false NOT NULL,
  is_bot BOOLEAN DEFAULT false NOT NULL,
  
  -- Content Settings
  default_post_visibility post_visibility DEFAULT 'public' NOT NULL,
  default_language VARCHAR(10) DEFAULT 'en' NOT NULL,
  timezone VARCHAR(50) DEFAULT 'UTC' NOT NULL,
  
  -- Statistics (denormalized for performance)
  followers_count INTEGER DEFAULT 0 NOT NULL,
  following_count INTEGER DEFAULT 0 NOT NULL,
  posts_count INTEGER DEFAULT 0 NOT NULL,
  
  -- Moderation
  is_silenced BOOLEAN DEFAULT false NOT NULL,
  is_suspended BOOLEAN DEFAULT false NOT NULL,
  silenced_at TIMESTAMPTZ,
  suspended_at TIMESTAMPTZ,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  last_posted_at TIMESTAMPTZ,
  
  -- Constraints
  CONSTRAINT profiles_actor_id_format CHECK (
    actor_id ~ '^https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$'
  ),
  CONSTRAINT profiles_valid_urls CHECK (
    (website_url IS NULL OR website_url ~ '^https?://') AND
    (avatar_url IS NULL OR avatar_url ~ '^https?://') AND
    (banner_url IS NULL OR banner_url ~ '^https?://')
  )
);

-- Indexes for profiles
CREATE UNIQUE INDEX idx_profiles_actor_id ON profiles(actor_id);
CREATE INDEX idx_profiles_domain ON profiles(domain) WHERE domain IS NOT NULL;
CREATE INDEX idx_profiles_discoverable ON profiles(is_discoverable, created_at) 
  WHERE is_discoverable = true;
CREATE INDEX idx_profiles_local ON profiles(is_local, created_at);
CREATE INDEX idx_profiles_search ON profiles 
  USING gin(to_tsvector('english', coalesce(display_name, '') || ' ' || coalesce(bio, '')));

-- ============================================================================
-- 3. POSTS TABLE (Content & Activities)
-- ============================================================================

CREATE TABLE posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  author_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  
  -- Content
  content TEXT NOT NULL,
  content_html TEXT,
  content_warning TEXT,
  language VARCHAR(10) DEFAULT 'en' NOT NULL,
  
  -- ActivityPub
  activity_id VARCHAR(500) UNIQUE NOT NULL,
  activity_type activitypub_object_type DEFAULT 'Note' NOT NULL,
  
  -- Threading
  in_reply_to_id UUID REFERENCES posts(id) ON DELETE SET NULL,
  root_post_id UUID REFERENCES posts(id) ON DELETE SET NULL,
  conversation_id UUID DEFAULT gen_random_uuid() NOT NULL,
  
  -- Visibility & Federation
  visibility post_visibility DEFAULT 'public' NOT NULL,
  is_local BOOLEAN DEFAULT true NOT NULL,
  is_sensitive BOOLEAN DEFAULT false NOT NULL,
  
  -- Engagement Metrics (denormalized)
  replies_count INTEGER DEFAULT 0 NOT NULL,
  reblogs_count INTEGER DEFAULT 0 NOT NULL,
  favourites_count INTEGER DEFAULT 0 NOT NULL,
  
  -- Content Features
  has_media BOOLEAN DEFAULT false NOT NULL,
  has_poll BOOLEAN DEFAULT false NOT NULL,
  poll_expires_at TIMESTAMPTZ,
  
  -- Moderation
  is_deleted BOOLEAN DEFAULT false NOT NULL,
  deleted_at TIMESTAMPTZ,
  deleted_by UUID REFERENCES users(id),
  
  -- Federation Status
  federation_status federation_status DEFAULT 'pending' NOT NULL,
  federated_at TIMESTAMPTZ,
  federation_failures INTEGER DEFAULT 0 NOT NULL,
  
  -- Timestamps
  published_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  edited_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  -- Constraints
  CONSTRAINT posts_content_length CHECK (length(content) <= 5000),
  CONSTRAINT posts_valid_reply CHECK (
    (in_reply_to_id IS NULL) OR 
    (in_reply_to_id IS NOT NULL AND root_post_id IS NOT NULL)
  ),
  CONSTRAINT posts_poll_expiry CHECK (
    (has_poll = false) OR 
    (has_poll = true AND poll_expires_at > NOW())
  )
);

-- Indexes for posts
CREATE INDEX idx_posts_author_published ON posts(author_id, published_at DESC) 
  WHERE is_deleted = false;
CREATE INDEX idx_posts_visibility_published ON posts(visibility, published_at DESC) 
  WHERE is_deleted = false;
CREATE INDEX idx_posts_conversation ON posts(conversation_id, published_at);
CREATE INDEX idx_posts_reply_to ON posts(in_reply_to_id) WHERE in_reply_to_id IS NOT NULL;
CREATE INDEX idx_posts_root ON posts(root_post_id) WHERE root_post_id IS NOT NULL;
CREATE INDEX idx_posts_federation ON posts(federation_status, created_at) 
  WHERE federation_status = 'pending';
CREATE INDEX idx_posts_search ON posts 
  USING gin(to_tsvector('english', content)) WHERE is_deleted = false;

-- ============================================================================
-- 4. SOCIAL GRAPH TABLES
-- ============================================================================

-- Follows
CREATE TABLE follows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  follower_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  following_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  
  -- ActivityPub
  activity_id VARCHAR(500) UNIQUE,
  
  -- Status
  status follow_status DEFAULT 'pending' NOT NULL,
  
  -- Timestamps
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  accepted_at TIMESTAMPTZ,
  
  UNIQUE(follower_id, following_id),
  CONSTRAINT follows_no_self_follow CHECK (follower_id != following_id)
);

CREATE INDEX idx_follows_follower ON follows(follower_id, status);
CREATE INDEX idx_follows_following ON follows(following_id, status);
CREATE INDEX idx_follows_pending ON follows(following_id) WHERE status = 'pending';

-- Blocks
CREATE TABLE blocks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  blocker_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  blocked_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  
  activity_id VARCHAR(500) UNIQUE,
  reason block_reason,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  UNIQUE(blocker_id, blocked_id),
  CONSTRAINT blocks_no_self_block CHECK (blocker_id != blocked_id)
);

CREATE INDEX idx_blocks_blocker ON blocks(blocker_id);
CREATE INDEX idx_blocks_blocked ON blocks(blocked_id);

-- Mutes
CREATE TABLE mutes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  muter_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  muted_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  
  hide_notifications BOOLEAN DEFAULT true NOT NULL,
  expires_at TIMESTAMPTZ,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  UNIQUE(muter_id, muted_id),
  CONSTRAINT mutes_no_self_mute CHECK (muter_id != muted_id)
);

CREATE INDEX idx_mutes_muter ON mutes(muter_id);
CREATE INDEX idx_mutes_expiry ON mutes(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- 5. ENGAGEMENT TABLES
-- ============================================================================

-- Favourites
CREATE TABLE favourites (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE NOT NULL,
  
  activity_id VARCHAR(500) UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  UNIQUE(user_id, post_id)
);

CREATE INDEX idx_favourites_user ON favourites(user_id, created_at DESC);
CREATE INDEX idx_favourites_post ON favourites(post_id, created_at DESC);

-- Reblogs
CREATE TABLE reblogs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE NOT NULL,
  
  activity_id VARCHAR(500) UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  UNIQUE(user_id, post_id)
);

CREATE INDEX idx_reblogs_user ON reblogs(user_id, created_at DESC);
CREATE INDEX idx_reblogs_post ON reblogs(post_id, created_at DESC);

-- ============================================================================
-- 6. CONTENT METADATA
-- ============================================================================

-- Media Attachments
CREATE TABLE media_attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  uploader_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  
  -- File Information
  original_filename VARCHAR(500) NOT NULL,
  file_size_bytes BIGINT NOT NULL,
  mime_type VARCHAR(100) NOT NULL,
  file_hash VARCHAR(128) UNIQUE NOT NULL, -- SHA-512 for deduplication
  
  -- Storage
  storage_provider storage_provider NOT NULL,
  storage_path TEXT NOT NULL,
  storage_url TEXT NOT NULL,
  thumbnail_url TEXT,
  
  -- Media Properties
  media_type media_type NOT NULL,
  width INTEGER,
  height INTEGER,
  duration_seconds DECIMAL(10,2),
  aspect_ratio DECIMAL(10,4),
  
  -- Accessibility
  alt_text TEXT,
  blurhash VARCHAR(100),
  
  -- Processing
  processing_status processing_status DEFAULT 'pending' NOT NULL,
  processed_at TIMESTAMPTZ,
  processing_error TEXT,
  
  -- Content Safety
  content_warning TEXT,
  is_sensitive BOOLEAN DEFAULT false NOT NULL,
  nsfw_score DECIMAL(3,2), -- AI moderation score
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  -- Constraints
  CONSTRAINT media_file_size_limit CHECK (file_size_bytes <= 1073741824), -- 1GB
  CONSTRAINT media_valid_dimensions CHECK (
    (width IS NULL AND height IS NULL) OR 
    (width > 0 AND height > 0)
  )
);

CREATE INDEX idx_media_post ON media_attachments(post_id);
CREATE INDEX idx_media_uploader ON media_attachments(uploader_id);
CREATE INDEX idx_media_hash ON media_attachments(file_hash);
CREATE INDEX idx_media_processing ON media_attachments(processing_status) 
  WHERE processing_status IN ('pending', 'processing');

-- Hashtags
CREATE TABLE hashtags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) UNIQUE NOT NULL,
  normalized_name VARCHAR(100) UNIQUE NOT NULL,
  
  -- Statistics
  usage_count BIGINT DEFAULT 0 NOT NULL,
  trending_score DECIMAL(10,4) DEFAULT 0 NOT NULL,
  last_used_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  -- Moderation
  is_banned BOOLEAN DEFAULT false NOT NULL,
  is_sensitive BOOLEAN DEFAULT false NOT NULL,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  CONSTRAINT hashtags_name_format CHECK (
    name ~ '^[a-zA-Z0-9_]{1,100}$'
  )
);

CREATE INDEX idx_hashtags_name ON hashtags(normalized_name);
CREATE INDEX idx_hashtags_trending ON hashtags(trending_score DESC, last_used_at DESC) 
  WHERE is_banned = false;
CREATE INDEX idx_hashtags_usage ON hashtags(usage_count DESC) WHERE is_banned = false;

-- Post Hashtags Junction
CREATE TABLE post_hashtags (
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  hashtag_id UUID REFERENCES hashtags(id) ON DELETE CASCADE,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  PRIMARY KEY (post_id, hashtag_id)
);

CREATE INDEX idx_post_hashtags_hashtag ON post_hashtags(hashtag_id, created_at DESC);

-- ============================================================================
-- 7. NOTIFICATIONS & COMMUNICATION
-- ============================================================================

CREATE TABLE notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_id UUID REFERENCES profiles(id) ON DELETE CASCADE NOT NULL,
  sender_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  
  -- Notification Details
  type notification_type NOT NULL,
  title VARCHAR(255),
  message TEXT,
  
  -- Related Objects
  post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  follow_id UUID REFERENCES follows(id) ON DELETE CASCADE,
  
  -- ActivityPub
  activity_id VARCHAR(500),
  
  -- Status
  is_read BOOLEAN DEFAULT false NOT NULL,
  read_at TIMESTAMPTZ,
  
  -- Delivery
  delivery_method delivery_method[] DEFAULT '{"in_app"}' NOT NULL,
  email_sent_at TIMESTAMPTZ,
  push_sent_at TIMESTAMPTZ,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  expires_at TIMESTAMPTZ,
  
  CONSTRAINT notifications_has_sender_or_system CHECK (
    (type IN ('system', 'admin_announcement') AND sender_id IS NULL) OR
    (type NOT IN ('system', 'admin_announcement') AND sender_id IS NOT NULL)
  )
);

CREATE INDEX idx_notifications_recipient_unread ON notifications(recipient_id, is_read, created_at DESC);
CREATE INDEX idx_notifications_type ON notifications(type, created_at DESC);
CREATE INDEX idx_notifications_expiry ON notifications(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- 8. SECURITY & SESSION MANAGEMENT
-- ============================================================================

-- User Sessions
CREATE TABLE user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
  
  -- Token Information
  token_hash VARCHAR(128) UNIQUE NOT NULL, -- SHA-512 hash
  refresh_token_hash VARCHAR(128) UNIQUE,
  
  -- Session Metadata
  device_fingerprint VARCHAR(128),
  user_agent TEXT,
  ip_address INET NOT NULL,
  country_code VARCHAR(2),
  city VARCHAR(100),
  
  -- Session Status
  is_active BOOLEAN DEFAULT true NOT NULL,
  last_activity_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  -- Security Features
  requires_2fa BOOLEAN DEFAULT false NOT NULL,
  is_suspicious BOOLEAN DEFAULT false NOT NULL,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  
  CONSTRAINT sessions_valid_expiry CHECK (expires_at > created_at)
);

CREATE INDEX idx_user_sessions_user ON user_sessions(user_id, is_active);
CREATE INDEX idx_user_sessions_token ON user_sessions(token_hash);
CREATE INDEX idx_user_sessions_refresh ON user_sessions(refresh_token_hash) 
  WHERE refresh_token_hash IS NOT NULL;
CREATE INDEX idx_user_sessions_expiry ON user_sessions(expires_at);
CREATE INDEX idx_user_sessions_cleanup ON user_sessions(created_at) 
  WHERE is_active = false;

-- Security Events Log
CREATE TABLE security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
  
  -- Event Details
  event_type security_event_type NOT NULL,
  event_data JSONB,
  
  -- Context
  ip_address INET,
  user_agent TEXT,
  country_code VARCHAR(2),
  
  -- Risk Assessment
  risk_score INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  is_blocked BOOLEAN DEFAULT false NOT NULL,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX idx_security_events_user ON security_events(user_id, created_at DESC);
CREATE INDEX idx_security_events_type ON security_events(event_type, created_at DESC);
CREATE INDEX idx_security_events_high_risk ON security_events(risk_score DESC, created_at DESC) 
  WHERE risk_score >= 70;

-- ============================================================================
-- 9. CONFIGURATION & SETTINGS
-- ============================================================================

-- User Settings
CREATE TABLE user_settings (
  user_id UUID REFERENCES users(id) PRIMARY KEY,
  
  -- Appearance
  theme theme_preference DEFAULT 'auto' NOT NULL,
  language VARCHAR(10) DEFAULT 'en' NOT NULL,
  timezone VARCHAR(50) DEFAULT 'UTC' NOT NULL,
  
  -- Privacy
  discoverable BOOLEAN DEFAULT true NOT NULL,
  indexable BOOLEAN DEFAULT true NOT NULL,
  show_followers BOOLEAN DEFAULT true NOT NULL,
  show_following BOOLEAN DEFAULT true NOT NULL,
  
  -- Notifications
  email_notifications BOOLEAN DEFAULT true NOT NULL,
  push_notifications BOOLEAN DEFAULT true NOT NULL,
  notification_sounds BOOLEAN DEFAULT true NOT NULL,
  
  -- Content
  default_post_visibility post_visibility DEFAULT 'public' NOT NULL,
  media_autoplay BOOLEAN DEFAULT false NOT NULL,
  show_sensitive_media BOOLEAN DEFAULT false NOT NULL,
  
  -- Accessibility
  reduce_motion BOOLEAN DEFAULT false NOT NULL,
  high_contrast BOOLEAN DEFAULT false NOT NULL,
  large_text BOOLEAN DEFAULT false NOT NULL,
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- ============================================================================
-- 10. MODERATION & ADMINISTRATION
-- ============================================================================

-- Reports
CREATE TABLE reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reporter_id UUID REFERENCES profiles(id) ON DELETE SET NULL,
  target_user_id UUID REFERENCES profiles(id) ON DELETE CASCADE,
  target_post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
  
  -- Report Details
  category report_category NOT NULL,
  subcategory VARCHAR(100),
  description TEXT NOT NULL,
  additional_info JSONB,
  
  -- Status
  status report_status DEFAULT 'open' NOT NULL,
  priority report_priority DEFAULT 'medium' NOT NULL,
  assigned_to UUID REFERENCES users(id),
  
  -- Resolution
  resolution_action moderation_action,
  resolution_note TEXT,
  resolved_at TIMESTAMPTZ,
  resolved_by UUID REFERENCES users(id),
  
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  
  CONSTRAINT reports_has_target CHECK (
    target_user_id IS NOT NULL OR target_post_id IS NOT NULL
  )
);

CREATE INDEX idx_reports_status ON reports(status, priority, created_at);
CREATE INDEX idx_reports_target_user ON reports(target_user_id) WHERE target_user_id IS NOT NULL;
CREATE INDEX idx_reports_target_post ON reports(target_post_id) WHERE target_post_id IS NOT NULL;
CREATE INDEX idx_reports_assigned ON reports(assigned_to) WHERE assigned_to IS NOT NULL;

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS on all user-facing tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE follows ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocks ENABLE ROW LEVEL SECURITY;
ALTER TABLE mutes ENABLE ROW LEVEL SECURITY;
ALTER TABLE favourites ENABLE ROW LEVEL SECURITY;
ALTER TABLE reblogs ENABLE ROW LEVEL SECURITY;
ALTER TABLE media_attachments ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_settings ENABLE ROW LEVEL SECURITY;

-- Helper function to get current authenticated user
CREATE OR REPLACE FUNCTION current_user_id() 
RETURNS UUID 
LANGUAGE sql 
SECURITY DEFINER 
STABLE
AS $$
  SELECT current_setting('app.current_user_id', true)::uuid;
$$;

-- Helper function to check if user can see profile
CREATE OR REPLACE FUNCTION can_view_profile(profile_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT 
    CASE 
      -- Can always view own profile
      WHEN profile_id = current_user_id() THEN true
      -- Can view if profile is discoverable
      WHEN EXISTS (
        SELECT 1 FROM profiles p 
        JOIN users u ON p.id = u.id 
        WHERE p.id = profile_id 
        AND p.is_discoverable = true 
        AND u.status = 'active'
      ) THEN true
      -- Can view if following (even if not discoverable)
      WHEN EXISTS (
        SELECT 1 FROM follows f 
        WHERE f.follower_id = current_user_id() 
        AND f.following_id = profile_id 
        AND f.status = 'accepted'
      ) THEN true
      ELSE false
    END;
$$;

-- RLS Policies for users table
CREATE POLICY "Users can view own account" ON users
  FOR SELECT USING (id = current_user_id());

CREATE POLICY "Users can update own account" ON users
  FOR UPDATE USING (id = current_user_id());

-- RLS Policies for profiles table
CREATE POLICY "Public profiles viewable" ON profiles
  FOR SELECT USING (can_view_profile(id));

CREATE POLICY "Users can update own profile" ON profiles
  FOR UPDATE USING (id = current_user_id());

CREATE POLICY "Users can create own profile" ON profiles
  FOR INSERT WITH CHECK (id = current_user_id());

-- RLS Policies for posts table
CREATE POLICY "Posts visibility policy" ON posts
  FOR SELECT USING (
    CASE visibility
      WHEN 'public' THEN true
      WHEN 'unlisted' THEN true
      WHEN 'followers' THEN 
        author_id = current_user_id() OR
        EXISTS (
          SELECT 1 FROM follows f 
          WHERE f.follower_id = current_user_id() 
          AND f.following_id = author_id 
          AND f.status = 'accepted'
        )
      WHEN 'direct' THEN author_id = current_user_id()
      ELSE false
    END
    AND is_deleted = false
  );

CREATE POLICY "Users can create own posts" ON posts
  FOR INSERT WITH CHECK (author_id = current_user_id());

CREATE POLICY "Users can update own posts" ON posts
  FOR UPDATE USING (author_id = current_user_id());

CREATE POLICY "Users can delete own posts" ON posts
  FOR DELETE USING (author_id = current_user_id());

-- RLS Policies for social graph
CREATE POLICY "Users can manage own follows" ON follows
  FOR ALL USING (follower_id = current_user_id());

CREATE POLICY "Users can see follows they're involved in" ON follows
  FOR SELECT USING (
    follower_id = current_user_id() OR 
    following_id = current_user_id()
  );

CREATE POLICY "Users can manage own blocks" ON blocks
  FOR ALL USING (blocker_id = current_user_id());

CREATE POLICY "Users can manage own mutes" ON mutes
  FOR ALL USING (muter_id = current_user_id());

-- RLS Policies for engagement
CREATE POLICY "Users can manage own favourites" ON favourites
  FOR ALL USING (user_id = current_user_id());

CREATE POLICY "Users can manage own reblogs" ON reblogs
  FOR ALL USING (user_id = current_user_id());

-- RLS Policies for notifications
CREATE POLICY "Users can view own notifications" ON notifications
  FOR SELECT USING (recipient_id = current_user_id());

CREATE POLICY "Users can update own notifications" ON notifications
  FOR UPDATE USING (recipient_id = current_user_id());

-- RLS Policies for sessions
CREATE POLICY "Users can manage own sessions" ON user_sessions
  FOR ALL USING (user_id = current_user_id());

-- RLS Policies for settings
CREATE POLICY "Users can manage own settings" ON user_settings
  FOR ALL USING (user_id = current_user_id());

-- ============================================================================
-- TRIGGERS FOR MAINTAINING DATA INTEGRITY
-- ============================================================================

-- Update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_posts_updated_at BEFORE UPDATE ON posts
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Maintain follower counts
CREATE OR REPLACE FUNCTION update_follower_counts()
RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.status = 'accepted' THEN
    UPDATE profiles SET followers_count = followers_count + 1 WHERE id = NEW.following_id;
    UPDATE profiles SET following_count = following_count + 1 WHERE id = NEW.follower_id;
  ELSIF TG_OP = 'DELETE' AND OLD.status = 'accepted' THEN
    UPDATE profiles SET followers_count = followers_count - 1 WHERE id = OLD.following_id;
    UPDATE profiles SET following_count = following_count - 1 WHERE id = OLD.follower_id;
  ELSIF TG_OP = 'UPDATE' THEN
    IF OLD.status != 'accepted' AND NEW.status = 'accepted' THEN
      UPDATE profiles SET followers_count = followers_count + 1 WHERE id = NEW.following_id;
      UPDATE profiles SET following_count = following_count + 1 WHERE id = NEW.follower_id;
    ELSIF OLD.status = 'accepted' AND NEW.status != 'accepted' THEN
      UPDATE profiles SET followers_count = followers_count - 1 WHERE id = NEW.following_id;
      UPDATE profiles SET following_count = following_count - 1 WHERE id = NEW.follower_id;
    END IF;
  END IF;
  
  RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER maintain_follower_counts
  AFTER INSERT OR UPDATE OR DELETE ON follows
  FOR EACH ROW EXECUTE FUNCTION update_follower_counts();

-- ============================================================================
-- PERFORMANCE OPTIMIZATION
-- ============================================================================

-- Partitioning for large tables (example for notifications)
-- CREATE TABLE notifications_y2024m01 PARTITION OF notifications
--   FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

-- Cleanup procedures
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
  deleted_count INTEGER;
BEGIN
  DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '7 days';
  GET DIAGNOSTICS deleted_count = ROW_COUNT;
  RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Additional composite indexes for common queries
CREATE INDEX idx_posts_timeline ON posts(visibility, published_at DESC, author_id) 
  WHERE is_deleted = false AND visibility IN ('public', 'unlisted');

CREATE INDEX idx_posts_replies ON posts(in_reply_to_id, published_at) 
  WHERE in_reply_to_id IS NOT NULL AND is_deleted = false;

CREATE INDEX idx_follows_accepted ON follows(following_id, follower_id) 
  WHERE status = 'accepted';

-- Partial indexes for better performance
CREATE INDEX idx_users_active ON users(created_at) WHERE status = 'active';
CREATE INDEX idx_profiles_local_discoverable ON profiles(created_at) 
  WHERE is_local = true AND is_discoverable = true;

-- ============================================================================
-- COMMENTS FOR DOCUMENTATION
-- ============================================================================

COMMENT ON TABLE users IS 'Core authentication and user identity table';
COMMENT ON TABLE profiles IS 'Public user profiles with ActivityPub federation support';
COMMENT ON TABLE posts IS 'User-generated content with ActivityPub compliance';
COMMENT ON TABLE follows IS 'Social graph relationships between users';
COMMENT ON TABLE notifications IS 'User notification system with multiple delivery methods';
COMMENT ON TABLE security_events IS 'Audit log for security-related events';

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================
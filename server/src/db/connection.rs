/* 

To establish, manage, maintain connections to supabase db.

$ Connection Pool Management
- Create and maintain db connections.
- Manage connection limits (efficient resource management).
- Health checks and recovery.

$ DB Config
- Setup SSL/TLS for supabase.
- Configure timeouts, retry logics, connection limits.
- ENV based settings (dev/prod).

$ Migration Management (Note: Using supabase right now, this is just a future safety)
- Interface to run db migration.
- Schema versioning and upgrades.

$ Security Integration
- RLS Support.
- User-Context.

*/


// Imports
use sqlx::{PgPool, ConnectOptions};
use sqlx::postgres::{PgConnectionOptions, PgPoolOptions};
use std::time::Duration;
use std::str::FromStr;
use uuid::Uuid;
use tracing::{info, error, debug};
use thiserror::Error;
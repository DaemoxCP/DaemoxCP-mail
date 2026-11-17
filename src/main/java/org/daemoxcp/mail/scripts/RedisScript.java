package org.daemoxcp.mail.scripts;

/**
 * Redis Installation Script for FreeBSD 15
 * On reinstall: completely removes Redis and reinstalls fresh
 *
 * Used by Rspamd for caching and learning
 */
public class RedisScript {

    private final String data;

    public RedisScript() {
        this.data = """
            #!/bin/sh
            # Redis Installation for FreeBSD 15
            # REINSTALL MODE: Completely removes Redis before reinstalling

            echo "=== Redis Installation ==="
            echo ""

            # Check root
            if [ "$(id -u)" -ne 0 ]; then
                echo "Error: Must run as root"
                exit 1
            fi

            #############################################
            # PHASE 1: COMPLETE CLEANUP
            #############################################

            echo "[CLEANUP] Stopping Redis..."
            service redis stop 2>/dev/null || true
            pkill -9 redis-server 2>/dev/null || true
            sleep 2

            echo "[CLEANUP] Removing Redis packages..."
            pkg delete -fy redis 2>/dev/null || true
            pkg autoremove -fy 2>/dev/null || true

            echo "[CLEANUP] Removing Redis data and config..."
            rm -rf /var/db/redis 2>/dev/null || true
            rm -rf /var/run/redis 2>/dev/null || true
            rm -rf /var/log/redis 2>/dev/null || true
            rm -f /usr/local/etc/redis.conf 2>/dev/null || true

            echo "[CLEANUP] Removing redis user..."
            pw userdel redis 2>/dev/null || true
            pw groupdel redis 2>/dev/null || true

            echo "[CLEANUP] Removing rc.conf entry..."
            sysrc -x redis_enable 2>/dev/null || true

            echo ""
            echo "[CLEANUP] Complete! Starting fresh installation..."
            echo ""

            #############################################
            # PHASE 2: FRESH INSTALLATION
            #############################################

            # Install Redis
            echo "[1/3] Installing Redis..."
            pkg install -y redis

            # Configure Redis
            echo "[2/3] Configuring Redis..."
            cat > /usr/local/etc/redis.conf << 'REDISCONF'
# Redis Configuration for Mail Panel
# Managed by FreeBSD Mail Panel

bind 127.0.0.1
port 6379
daemonize yes
pidfile /var/run/redis/redis.pid

loglevel notice
logfile /var/log/redis/redis.log

databases 16

# Persistence
save 900 1
save 300 10
save 60 10000

dir /var/db/redis
dbfilename dump.rdb

# Memory
maxmemory 256mb
maxmemory-policy allkeys-lru

# Security
protected-mode yes
REDISCONF

            # Create directories
            mkdir -p /var/run/redis
            mkdir -p /var/log/redis
            mkdir -p /var/db/redis
            chown redis:redis /var/run/redis
            chown redis:redis /var/log/redis
            chown redis:redis /var/db/redis

            # Enable and start
            echo "[3/3] Enabling service..."
            sysrc redis_enable="YES"
            service redis start

            echo ""
            echo "=== Redis Installation Complete ==="
            echo ""
            echo "Configuration: /usr/local/etc/redis.conf"
            echo "Port:          6379 (localhost only)"
            echo ""
            """;
    }

    public String getScriptContent() {
        return this.data;
    }
}

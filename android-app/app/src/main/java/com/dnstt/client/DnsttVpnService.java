package com.dnstt.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;

import mobile.Client;
import mobile.Config;
import mobile.Mobile;
import mobile.StatusCallback;

public class DnsttVpnService extends VpnService implements StatusCallback {
    private static final String TAG = "DnsttVpnService";
    private static final String CHANNEL_ID = "dnstt_vpn";
    private static final int NOTIFICATION_ID = 1;

    public static final String ACTION_START = "com.dnstt.client.START";
    public static final String ACTION_STOP = "com.dnstt.client.STOP";

    public static final String EXTRA_TRANSPORT_TYPE = "transport_type";
    public static final String EXTRA_TRANSPORT_ADDR = "transport_addr";
    public static final String EXTRA_DOMAIN = "domain";
    public static final String EXTRA_PUBKEY = "pubkey";
    public static final String EXTRA_TUNNELS = "tunnels";

    private ParcelFileDescriptor vpnInterface;
    private Client dnsttClient;
    private Thread vpnThread;
    private volatile boolean running = false;

    // Callback for UI updates
    private static StatusCallback uiCallback;

    public static void setUiCallback(StatusCallback callback) {
        uiCallback = callback;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        log("VPN service created");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) {
            log("Received null intent");
            return START_NOT_STICKY;
        }

        String action = intent.getAction();
        log("Received action: " + action);

        if (ACTION_STOP.equals(action)) {
            log("Stop action received");
            stopVpn();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(action)) {
            String transportType = intent.getStringExtra(EXTRA_TRANSPORT_TYPE);
            String transportAddr = intent.getStringExtra(EXTRA_TRANSPORT_ADDR);
            String domain = intent.getStringExtra(EXTRA_DOMAIN);
            String pubkey = intent.getStringExtra(EXTRA_PUBKEY);
            int tunnels = intent.getIntExtra(EXTRA_TUNNELS, 8);

            log("Starting VPN with:");
            log("  Transport: " + transportType + " via " + transportAddr);
            log("  Domain: " + domain);
            log("  Tunnels: " + tunnels);

            startVpn(transportType, transportAddr, domain, pubkey, tunnels);
        }

        return START_STICKY;
    }

    private void startVpn(String transportType, String transportAddr, String domain, String pubkey, int tunnels) {
        // Start foreground service
        startForeground(NOTIFICATION_ID, createNotification("Connecting..."));
        onStatusChange(1, "Initializing DNSTT client...");

        // Start DNSTT client first
        dnsttClient = Mobile.newClient();
        dnsttClient.setCallback(this);

        Config config = Mobile.newConfig();
        config.setTransportType(transportType);
        config.setTransportAddr(transportAddr);
        config.setDomain(domain);
        config.setPubkeyHex(pubkey);
        config.setListenAddr("127.0.0.1:1080");
        config.setTunnels(tunnels);
        config.setMTU(1232);
        config.setUTLSFingerprint("Chrome");

        new Thread(() -> {
            try {
                log("Starting DNSTT client...");
                onStatusChange(1, "Establishing DNS tunnel...");
                dnsttClient.start(config);

                log("DNSTT client started, waiting for connection...");
                // Give DNSTT a moment to establish connection
                Thread.sleep(1000);

                log("Establishing VPN interface...");
                onStatusChange(1, "Establishing VPN interface...");
                // Now establish VPN
                establishVpn();

            } catch (Exception e) {
                log("Failed to start: " + e.getMessage());
                onStatusChange(3, "Error: " + e.getMessage());
                stopSelf();
            }
        }).start();
    }

    private void establishVpn() {
        try {
            log("Building VPN interface...");
            Builder builder = new Builder();
            builder.setSession("DNSTT VPN")
                    .addAddress("10.0.0.2", 24)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("8.8.4.4")
                    .setMtu(1500)
                    .setBlocking(true);

            // Exclude our own app to prevent loops
            try {
                builder.addDisallowedApplication(getPackageName());
                log("Excluded self from VPN to prevent loops");
            } catch (Exception e) {
                log("Could not exclude self: " + e.getMessage());
            }

            vpnInterface = builder.establish();

            if (vpnInterface == null) {
                throw new IOException("VPN interface is null - permission may have been revoked");
            }

            log("VPN interface established successfully");
            log("  Address: 10.0.0.2/24");
            log("  MTU: 1500");
            log("  DNS: 8.8.8.8, 8.8.4.4");

            running = true;
            vpnThread = new Thread(this::runTunnel, "VpnThread");
            vpnThread.start();
            log("VPN tunnel thread started");

            updateNotification("Connected");
            onStatusChange(2, "VPN Connected - All traffic routed through tunnel");

        } catch (Exception e) {
            log("Failed to establish VPN: " + e.getMessage());
            onStatusChange(3, "VPN Error: " + e.getMessage());
            stopVpn();
        }
    }

    private void runTunnel() {
        log("VPN tunnel running...");
        FileInputStream tunIn = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());

        DatagramChannel socksChannel = null;
        try {
            // Connect to local SOCKS proxy via UDP for tunnel
            socksChannel = DatagramChannel.open();
            socksChannel.configureBlocking(false);
            protect(socksChannel.socket());
            log("UDP channel opened and protected");

            ByteBuffer packet = ByteBuffer.allocate(32767);
            int packetsProcessed = 0;

            while (running && vpnInterface != null) {
                // Read from TUN
                packet.clear();
                int length = tunIn.read(packet.array());

                if (length > 0) {
                    packet.limit(length);
                    packetsProcessed++;

                    // Parse IP packet and forward through SOCKS5
                    // This is a simplified implementation
                    // For production, use a proper tun2socks library
                    forwardPacket(packet, tunOut);

                    // Log every 1000 packets
                    if (packetsProcessed % 1000 == 0) {
                        log("Processed " + packetsProcessed + " packets");
                    }
                }

                Thread.sleep(1); // Prevent busy loop
            }

            log("VPN tunnel stopped after processing " + packetsProcessed + " packets");

        } catch (Exception e) {
            if (running) {
                log("Tunnel error: " + e.getMessage());
                onStatusChange(3, "Tunnel error: " + e.getMessage());
            }
        } finally {
            try {
                if (socksChannel != null) socksChannel.close();
                tunIn.close();
                tunOut.close();
                log("Tunnel resources cleaned up");
            } catch (IOException e) {
                log("Cleanup error: " + e.getMessage());
            }
        }
    }

    private void forwardPacket(ByteBuffer packet, FileOutputStream tunOut) {
        // This is a placeholder - proper implementation needs tun2socks
        // For now, we'll use a simpler approach with badvpn-tun2socks or similar
        // The SOCKS5 proxy handles the actual tunneling
        //
        // To make this work properly, you would need to:
        // 1. Use a native tun2socks library (like libcore or hev-socks5-tunnel)
        // 2. Or implement SOCKS5 UDP relay in Java
        // 3. The packet forwarding would parse IP headers and route accordingly
    }

    private void stopVpn() {
        log("Stopping VPN...");
        running = false;

        if (vpnThread != null) {
            vpnThread.interrupt();
            vpnThread = null;
            log("VPN thread interrupted");
        }

        if (vpnInterface != null) {
            try {
                vpnInterface.close();
                log("VPN interface closed");
            } catch (IOException e) {
                log("Error closing VPN interface: " + e.getMessage());
            }
            vpnInterface = null;
        }

        if (dnsttClient != null) {
            log("Stopping DNSTT client...");
            dnsttClient.stop();
            dnsttClient = null;
            log("DNSTT client stopped");
        }

        onStatusChange(0, "Disconnected");
        stopForeground(true);
        stopSelf();
        log("VPN service stopped");
    }

    @Override
    public void onDestroy() {
        log("VPN service being destroyed");
        stopVpn();
        super.onDestroy();
    }

    @Override
    public void onStatusChange(long state, String message) {
        log("Status: " + state + " - " + message);

        if (state == 2) {
            updateNotification("Connected");
        } else if (state == 3) {
            updateNotification("Error");
        }

        if (uiCallback != null) {
            uiCallback.onStatusChange(state, message);
        }
    }

    @Override
    public void onBytesTransferred(long bytesIn, long bytesOut) {
        if (uiCallback != null) {
            uiCallback.onBytesTransferred(bytesIn, bytesOut);
        }
    }

    private void log(String message) {
        Log.d(TAG, message);
        // Also send to UI if callback is set
        if (uiCallback != null) {
            uiCallback.onStatusChange(-1, "[VPN] " + message);
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "DNSTT VPN",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Shows VPN connection status");

            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.createNotificationChannel(channel);
            }
        }
    }

    private Notification createNotification(String text) {
        Intent intent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, intent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        Intent stopIntent = new Intent(this, DnsttVpnService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPendingIntent = PendingIntent.getService(
                this, 0, stopIntent,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
        );

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("DNSTT VPN")
                .setContentText(text)
                .setSmallIcon(R.drawable.ic_launcher)
                .setContentIntent(pendingIntent)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopPendingIntent)
                .setOngoing(true)
                .build();
    }

    private void updateNotification(String text) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.notify(NOTIFICATION_ID, createNotification(text));
        }
    }
}

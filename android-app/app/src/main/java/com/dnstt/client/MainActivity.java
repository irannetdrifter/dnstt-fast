package com.dnstt.client;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;
import com.google.android.material.textfield.TextInputEditText;

import mobile.Client;
import mobile.Config;
import mobile.StatusCallback;

public class MainActivity extends AppCompatActivity implements StatusCallback {

    private static final String PREFS_NAME = "dnstt_prefs";

    private Client client;
    private Handler handler;
    private boolean isConnected = false;
    private boolean vpnMode = true;
    private boolean autoConnect = false;
    private boolean useRandomDns = true;
    private boolean hasAutoConnected = false;

    private DnsServerManager dnsServerManager;

    // UI Elements
    private TextView statusText;
    private MaterialButton connectButton;
    private TextView bytesInText;
    private TextView bytesOutText;
    private TextView streamsText;
    private TextView logText;
    private AutoCompleteTextView transportType;
    private TextInputEditText transportAddr;
    private TextInputEditText domain;
    private TextInputEditText pubkey;
    private TextInputEditText tunnels;
    private SwitchMaterial vpnModeSwitch;
    private SwitchMaterial autoConnectSwitch;
    private SwitchMaterial randomDnsSwitch;

    // VPN permission launcher
    private ActivityResultLauncher<Intent> vpnPermissionLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        handler = new Handler(Looper.getMainLooper());
        client = mobile.Mobile.newClient();
        client.setCallback(this);

        // Initialize DNS server manager
        dnsServerManager = new DnsServerManager(this);
        appendLog("Loaded " + dnsServerManager.getServerCount() + " DNS servers");

        // Register VPN permission launcher
        vpnPermissionLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        appendLog("VPN permission granted");
                        startVpnService();
                    } else {
                        appendLog("VPN permission denied by user");
                        setInputsEnabled(true);
                    }
                }
        );

        initViews();
        loadSettings();
        setupTransportDropdown();

        // Set up UI callback for VPN service
        DnsttVpnService.setUiCallback(this);

        appendLog("DNSTT Client initialized");
        appendLog("VPN mode: " + (vpnMode ? "enabled" : "disabled"));
        appendLog("Auto-connect: " + (autoConnect ? "enabled" : "disabled"));
        appendLog("Random DNS: " + (useRandomDns ? "enabled" : "disabled"));

        // Auto-connect if enabled and settings are valid
        if (autoConnect && !hasAutoConnected && hasValidSettings()) {
            hasAutoConnected = true;
            appendLog("Auto-connecting...");

            // If using random DNS and transport is UDP, pick a random server
            if (useRandomDns && transportType.getText().toString().equalsIgnoreCase("UDP")) {
                String randomServer = dnsServerManager.formatForUdp(dnsServerManager.getRandomServer());
                transportAddr.setText(randomServer);
                appendLog("Selected random DNS server: " + randomServer);
            }

            handler.postDelayed(this::connect, 500);
        }
    }

    private boolean hasValidSettings() {
        String pubkeyStr = getText(pubkey);
        String domainStr = getText(domain);
        return pubkeyStr != null && !pubkeyStr.isEmpty() &&
               domainStr != null && !domainStr.isEmpty();
    }

    private void initViews() {
        statusText = findViewById(R.id.statusText);
        connectButton = findViewById(R.id.connectButton);
        bytesInText = findViewById(R.id.bytesInText);
        bytesOutText = findViewById(R.id.bytesOutText);
        streamsText = findViewById(R.id.streamsText);
        logText = findViewById(R.id.logText);
        transportType = findViewById(R.id.transportType);
        transportAddr = findViewById(R.id.transportAddr);
        domain = findViewById(R.id.domain);
        pubkey = findViewById(R.id.pubkey);
        tunnels = findViewById(R.id.tunnels);
        vpnModeSwitch = findViewById(R.id.vpnModeSwitch);
        autoConnectSwitch = findViewById(R.id.autoConnectSwitch);
        randomDnsSwitch = findViewById(R.id.randomDnsSwitch);

        connectButton.setOnClickListener(v -> {
            if (isConnected) {
                disconnect();
            } else {
                connect();
            }
        });

        vpnModeSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            vpnMode = isChecked;
            appendLog("VPN mode " + (isChecked ? "enabled" : "disabled"));
            saveSettings();
        });

        autoConnectSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            autoConnect = isChecked;
            appendLog("Auto-connect " + (isChecked ? "enabled" : "disabled"));
            saveSettings();
        });

        randomDnsSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            useRandomDns = isChecked;
            appendLog("Random DNS " + (isChecked ? "enabled" : "disabled"));
            if (isChecked && transportType.getText().toString().equalsIgnoreCase("UDP")) {
                String randomServer = dnsServerManager.formatForUdp(dnsServerManager.getRandomServer());
                transportAddr.setText(randomServer);
                appendLog("Selected random DNS: " + randomServer);
            }
            saveSettings();
        });
    }

    private void setupTransportDropdown() {
        String[] types = {"DoH", "DoT", "UDP"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_dropdown_item_1line, types);
        transportType.setAdapter(adapter);

        transportType.setOnItemClickListener((parent, view, position, id) -> {
            switch (position) {
                case 0: // DoH
                    transportAddr.setText("https://dns.google/dns-query");
                    appendLog("Transport: DoH (DNS over HTTPS)");
                    break;
                case 1: // DoT
                    transportAddr.setText("dns.google:853");
                    appendLog("Transport: DoT (DNS over TLS)");
                    break;
                case 2: // UDP
                    if (useRandomDns) {
                        String randomServer = dnsServerManager.formatForUdp(dnsServerManager.getRandomServer());
                        transportAddr.setText(randomServer);
                        appendLog("Transport: UDP - Random server: " + randomServer);
                    } else {
                        transportAddr.setText("1.1.1.1:53");
                        appendLog("Transport: UDP");
                    }
                    break;
            }
        });
    }

    private void connect() {
        if (!hasValidSettings()) {
            appendLog("Error: Domain and public key are required");
            return;
        }

        saveSettings();
        setInputsEnabled(false);

        String type = transportType.getText().toString();
        String addr = getText(transportAddr);
        String dom = getText(domain);
        int numTunnels = 8;
        try {
            numTunnels = Integer.parseInt(getText(tunnels));
        } catch (NumberFormatException ignored) {}

        // If using random DNS and UDP, pick a new server
        if (useRandomDns && type.equalsIgnoreCase("UDP")) {
            addr = dnsServerManager.formatForUdp(dnsServerManager.getRandomServer());
            transportAddr.setText(addr);
            appendLog("Using random DNS server: " + addr);
        }

        appendLog("Connecting to " + dom);
        appendLog("Transport: " + type + " via " + addr);
        appendLog("Tunnels: " + numTunnels);

        if (vpnMode) {
            appendLog("Requesting VPN permission...");
            Intent vpnIntent = VpnService.prepare(this);
            if (vpnIntent != null) {
                vpnPermissionLauncher.launch(vpnIntent);
            } else {
                appendLog("VPN permission already granted");
                startVpnService();
            }
        } else {
            appendLog("Starting SOCKS5 proxy mode...");
            connectSocksProxy();
        }
    }

    private void startVpnService() {
        appendLog("Starting VPN service...");
        Intent intent = new Intent(this, DnsttVpnService.class);
        intent.setAction(DnsttVpnService.ACTION_START);
        intent.putExtra(DnsttVpnService.EXTRA_TRANSPORT_TYPE, transportType.getText().toString().toLowerCase());
        intent.putExtra(DnsttVpnService.EXTRA_TRANSPORT_ADDR, getText(transportAddr));
        intent.putExtra(DnsttVpnService.EXTRA_DOMAIN, getText(domain));
        intent.putExtra(DnsttVpnService.EXTRA_PUBKEY, getText(pubkey));

        try {
            intent.putExtra(DnsttVpnService.EXTRA_TUNNELS, Integer.parseInt(getText(tunnels)));
        } catch (NumberFormatException e) {
            intent.putExtra(DnsttVpnService.EXTRA_TUNNELS, 8);
        }

        startForegroundService(intent);
    }

    private void connectSocksProxy() {
        Config config = mobile.Mobile.newConfig();

        String type = transportType.getText().toString().toLowerCase();
        config.setTransportType(type);
        config.setTransportAddr(getText(transportAddr));
        config.setDomain(getText(domain));
        config.setPubkeyHex(getText(pubkey));
        config.setListenAddr("127.0.0.1:1080");

        try {
            config.setTunnels(Integer.parseInt(getText(tunnels)));
        } catch (NumberFormatException e) {
            config.setTunnels(8);
        }

        config.setMTU(1232);
        config.setUTLSFingerprint("Chrome");
        config.setUseZstd(true); // Enable zstd compression (server has it on by default)
        appendLog("Zstd compression: enabled");

        new Thread(() -> {
            try {
                appendLog("Establishing tunnels...");
                client.start(config);
            } catch (Exception e) {
                handler.post(() -> {
                    appendLog("Connection error: " + e.getMessage());
                    appendLog("Stack trace: " + android.util.Log.getStackTraceString(e));
                    setInputsEnabled(true);
                });
            }
        }).start();
    }

    private void disconnect() {
        appendLog("Disconnecting...");
        if (vpnMode) {
            Intent intent = new Intent(this, DnsttVpnService.class);
            intent.setAction(DnsttVpnService.ACTION_STOP);
            startService(intent);
        } else {
            new Thread(() -> {
                client.stop();
                handler.post(() -> setInputsEnabled(true));
            }).start();
        }
    }

    private String getText(TextInputEditText editText) {
        return editText.getText() != null ? editText.getText().toString() : "";
    }

    private void setInputsEnabled(boolean enabled) {
        transportType.setEnabled(enabled);
        transportAddr.setEnabled(enabled);
        domain.setEnabled(enabled);
        pubkey.setEnabled(enabled);
        tunnels.setEnabled(enabled);
        vpnModeSwitch.setEnabled(enabled);
        autoConnectSwitch.setEnabled(enabled);
        randomDnsSwitch.setEnabled(enabled);
    }

    private void appendLog(String message) {
        handler.post(() -> {
            String timestamp = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                    .format(new java.util.Date());
            String logLine = "[" + timestamp + "] " + message;

            String current = logText.getText().toString();
            String newText = logLine + "\n" + current;
            // Keep last 50 lines for more history
            String[] lines = newText.split("\n");
            if (lines.length > 50) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 50; i++) {
                    sb.append(lines[i]).append("\n");
                }
                newText = sb.toString();
            }
            logText.setText(newText);
        });
    }

    @Override
    public void onStatusChange(long state, String message) {
        handler.post(() -> {
            // Don't show internal VPN logs in status bar, just in log
            if (state == -1) {
                appendLog(message);
                return;
            }

            appendLog(message);

            switch ((int) state) {
                case 0: // Stopped
                    statusText.setText(R.string.status_disconnected);
                    statusText.setTextColor(getColor(R.color.disconnected));
                    connectButton.setText(R.string.connect);
                    isConnected = false;
                    setInputsEnabled(true);
                    break;
                case 1: // Connecting
                    statusText.setText(R.string.status_connecting);
                    statusText.setTextColor(getColor(R.color.connecting));
                    connectButton.setText(R.string.disconnect);
                    isConnected = false;
                    break;
                case 2: // Connected
                    statusText.setText(R.string.status_connected);
                    statusText.setTextColor(getColor(R.color.connected));
                    connectButton.setText(R.string.disconnect);
                    isConnected = true;
                    break;
                case 3: // Error
                    statusText.setText("Error");
                    statusText.setTextColor(getColor(R.color.disconnected));
                    connectButton.setText(R.string.connect);
                    isConnected = false;
                    setInputsEnabled(true);
                    break;
            }
        });
    }

    @Override
    public void onBytesTransferred(long bytesIn, long bytesOut) {
        handler.post(() -> {
            bytesInText.setText(formatBytes(bytesIn));
            bytesOutText.setText(formatBytes(bytesOut));
            if (!vpnMode) {
                streamsText.setText(String.valueOf(client.getActiveStreams()));
            }
        });
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private void saveSettings() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        prefs.edit()
                .putString("transportType", transportType.getText().toString())
                .putString("transportAddr", getText(transportAddr))
                .putString("domain", getText(domain))
                .putString("pubkey", getText(pubkey))
                .putString("tunnels", getText(tunnels))
                .putBoolean("vpnMode", vpnMode)
                .putBoolean("autoConnect", autoConnect)
                .putBoolean("useRandomDns", useRandomDns)
                .apply();
    }

    private void loadSettings() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE);

        String type = prefs.getString("transportType", "UDP");
        transportType.setText(type, false);

        transportAddr.setText(prefs.getString("transportAddr", "1.1.1.1:53"));
        domain.setText(prefs.getString("domain", "t.example.com"));
        pubkey.setText(prefs.getString("pubkey", ""));
        tunnels.setText(prefs.getString("tunnels", "8"));

        vpnMode = prefs.getBoolean("vpnMode", true);
        vpnModeSwitch.setChecked(vpnMode);

        autoConnect = prefs.getBoolean("autoConnect", false);
        autoConnectSwitch.setChecked(autoConnect);

        useRandomDns = prefs.getBoolean("useRandomDns", true);
        randomDnsSwitch.setChecked(useRandomDns);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        DnsttVpnService.setUiCallback(null);
        if (!vpnMode && isConnected) {
            client.stop();
        }
    }
}

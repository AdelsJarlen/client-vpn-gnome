// Client VPN Quick Settings toggle for GNOME Shell 50.
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import {QuickMenuToggle, SystemIndicator} from 'resource:///org/gnome/shell/ui/quickSettings.js';

const BUS_NAME = 'io.github.AdelsJarlen.ClientVpn1';
const OBJECT_PATH = '/io/github/AdelsJarlen/ClientVpn1';
const APP_BINARY = '/usr/bin/client-vpn';

const IFACE_XML = `
<node>
  <interface name="io.github.AdelsJarlen.ClientVpn1">
    <method name="Disconnect"/>
    <property name="State" type="s" access="read"/>
    <property name="ProfileName" type="s" access="read"/>
    <property name="ServerAddress" type="s" access="read"/>
    <property name="TunnelAddress" type="s" access="read"/>
    <property name="ConnectedSince" type="x" access="read"/>
    <property name="BytesIn" type="t" access="read"/>
    <property name="BytesOut" type="t" access="read"/>
    <property name="LastError" type="s" access="read"/>
  </interface>
</node>`;
const VpnProxy = Gio.DBusProxy.makeProxyWrapper(IFACE_XML);

const STATES = {
    disconnected: ['Off', 'network-vpn-disabled-symbolic'],
    authenticating: ['Signing in…', 'network-vpn-acquiring-symbolic'],
    connecting: ['Connecting…', 'network-vpn-acquiring-symbolic'],
    connected: ['Connected', 'network-vpn-symbolic'],
    error: ['Error', 'network-vpn-disabled-symbolic'],
};

function formatDuration(seconds) {
    seconds = Math.max(0, Math.floor(seconds));
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const mm = String(m).padStart(2, '0');
    const ss = String(s).padStart(2, '0');
    return h > 0 ? `${h}:${mm}:${ss}` : `${m}:${ss}`;
}

const ClientVpnToggle = GObject.registerClass({
    Signals: {'vpn-state-changed': {param_types: [GObject.TYPE_STRING]}},
}, class ClientVpnToggle extends QuickMenuToggle {
    _init() {
        super._init({title: 'Client VPN', iconName: 'network-vpn-disabled-symbolic', toggleMode: false});

        this.menu.setHeader('network-vpn-symbolic', 'Client VPN');
        this._infoSection = new PopupMenu.PopupMenuSection();
        this.menu.addMenuItem(this._infoSection);
        this._rows = {};
        for (const [key, label] of [['ProfileName', 'Profile'], ['ServerAddress', 'Server'],
            ['TunnelAddress', 'Tunnel'], ['uptime', 'Connected for'], ['traffic', 'Received / sent']]) {
            const item = new PopupMenu.PopupMenuItem('', {reactive: false});
            item.label.clutter_text.set_ellipsize(3); // END
            this._rows[key] = {item, label};
            this._infoSection.addMenuItem(item);
        }
        this.menu.addMenuItem(new PopupMenu.PopupSeparatorMenuItem());
        this._actionItem = this.menu.addAction('Connect', () => this._toggle());
        this.menu.addAction('Open Client VPN', () => this._launchApp([]));

        this.connect('clicked', () => this._toggle());

        this._proxy = null;
        this._cancellable = new Gio.Cancellable();
        new VpnProxy(Gio.DBus.system, BUS_NAME, OBJECT_PATH, (proxy, error) => {
            if (error) {
                if (!this._cancellable.is_cancelled())
                    console.warn(`Client VPN: ${error.message}`);
                this._sync();
                return;
            }
            this._proxy = proxy;
            this._propsId = proxy.connect('g-properties-changed', () => this._sync());
            this._ownerId = proxy.connect('notify::g-name-owner', () => this._sync());
            this._sync();
        }, this._cancellable, Gio.DBusProxyFlags.DO_NOT_AUTO_START);

        this._timerId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, 1, () => {
            if (this._state === 'connected' && this.menu.isOpen)
                this._sync();
            return GLib.SOURCE_CONTINUE;
        });
        this._sync();
    }

    get _state() {
        if (!this._proxy || !this._proxy.g_name_owner)
            return 'disconnected';
        return this._proxy.State || 'disconnected';
    }

    _sync() {
        const state = this._state;
        const [subtitle, icon] = STATES[state] ?? [state, 'network-vpn-symbolic'];
        const p = this._proxy && this._proxy.g_name_owner ? this._proxy : null;
        const profile = p?.ProfileName || '';

        this.checked = state === 'connected' || state === 'connecting' || state === 'authenticating';
        this.iconName = icon;
        this.subtitle = state === 'error' ? (p?.LastError || subtitle) : (state === 'disconnected' ? null : subtitle);
        this._actionItem.label.text = this.checked ? (state === 'connected' ? 'Disconnect' : 'Cancel') : 'Connect';
        this.menu.setHeader(icon, 'Client VPN', profile || 'No profile imported');

        const values = {
            ProfileName: profile || '—',
            ServerAddress: p?.ServerAddress || '—',
            TunnelAddress: p?.TunnelAddress || '—',
            uptime: state === 'connected' && p?.ConnectedSince
                ? formatDuration(Date.now() / 1000 - Number(p.ConnectedSince)) : '—',
            traffic: p ? `${GLib.format_size(Number(p.BytesIn || 0))} / ${GLib.format_size(Number(p.BytesOut || 0))}` : '—',
        };
        for (const [key, {item, label}] of Object.entries(this._rows)) {
            item.label.text = `${label}: ${values[key]}`;
            item.visible = state === 'connected' || key === 'ProfileName';
        }
        this.emit('vpn-state-changed', state);
    }

    _toggle() {
        if (this.checked)
            this._disconnect();
        else
            this._launchApp(['--connect']);
        Main.panel.closeQuickSettings();
    }

    _disconnect() {
        // Ask the app to disconnect: it cancels a pending browser login as
        // well, and polkit authorization is evaluated for the user session.
        this._launchApp(['--disconnect']);
    }

    _launchApp(args) {
        try {
            const proc = Gio.Subprocess.new([APP_BINARY, ...args], Gio.SubprocessFlags.NONE);
            proc.wait_async(null, null);
        } catch (e) {
            Main.notifyError('Client VPN', `Could not start the Client VPN app: ${e.message}`);
        }
    }

    destroy() {
        this._cancellable.cancel();
        if (this._timerId) {
            GLib.source_remove(this._timerId);
            this._timerId = 0;
        }
        if (this._proxy) {
            this._proxy.disconnect(this._propsId);
            this._proxy.disconnect(this._ownerId);
            this._proxy = null;
        }
        super.destroy();
    }
});

const ClientVpnIndicator = GObject.registerClass(
class ClientVpnIndicator extends SystemIndicator {
    _init() {
        super._init();
        this._indicator = this._addIndicator();
        this._indicator.icon_name = 'network-vpn-symbolic';
        this._indicator.visible = false;

        const toggle = new ClientVpnToggle();
        this._stateId = toggle.connect('vpn-state-changed', (_t, state) => {
            this._indicator.visible = state === 'connected';
        });
        this.quickSettingsItems.push(toggle);
        this._toggle = toggle;
    }

    destroy() {
        this.quickSettingsItems.forEach(item => item.destroy());
        super.destroy();
    }
});

export default class ClientVpnExtension extends Extension {
    enable() {
        this._indicator = new ClientVpnIndicator();
        Main.panel.statusArea.quickSettings.addExternalIndicator(this._indicator);
    }

    disable() {
        this._indicator?.destroy();
        this._indicator = null;
    }
}

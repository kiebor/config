user_pref("app.shield.optoutstudies.enabled", false);

// Disable about:config warning
user_pref("browser.aboutConfig.showWarning", false);

// Enable "do not track"
user_pref("privacy.trackingprotection.enabled", true);

// Disable Firefox Normandy
user_pref("app.normandy.enabled", true);
user_pref("app.normandy.first_run", false);
user_pref("app.normandy.dev_mode", false);
user_pref("beacon.enabled", false);

// Check if Firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser", true);

// Minimal Firefox new tabpage
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// Disable Firefox Pocket
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.api", "");
user_pref("extensions.pocket.oAuthConsumerKey", "");
user_pref("extensions.pocket.onSaveRecs", false);
user_pref("extensions.pocket.showHome", false);
user_pref("extensions.pocket.site", "");
user_pref("browser.newtabpage.activity-stream.discoverystream.saveToPocketCard.enabled", false);
user_pref("browser.newtabpage.activity-stream.discoverystream.sendToPocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);

// Disable telemetry
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.pioneer-new-studies-available", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.server_owner", "");
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry.structuredIngestion.endpoint", "");
user_pref("browser.newtabpage.activity-stream.telemetry.ut.events", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("security.identitypopup.recordEventTelemetry", false);
user_pref("security.certerrors.recordEventTelemetry", false);
user_pref("security.app_menu.recordEventTelemetry", false);
user_pref("security.protectionspopup.recordEventTelemetry", false);
user_pref("network.trr.confirmation_telemetry_enabled", false);
user_pref("dom.security.unexpected_system_load_telemetry_enabled", false);

// Disable Firefox Accounts
user_pref("identity.fxaccounts.enabled", false);
user_pref("browser.newtabpage.activity-stream.fxaccounts.endpoint", "");
user_pref("identity.fxaccounts.auth.uri", "");
user_pref("identity.fxaccounts.commands.enabled", false);
user_pref("identity.fxaccounts.toolbar.enabled", false);
user_pref("identity.fxaccounts.pairing.enabled", false);

// Disable Firefox View
user_pref("browser.tabs.firefox-view", false);

// Enable HTTPS only
user_pref("dom.security.https_only_mode", true);

// Disable Google Safe Browsing
user_pref("browser.safebrowsing.allowOverride", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", false);
user_pref("browser.safebrowsing.downloads.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.enabled", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous", false);
user_pref("browser.safebrowsing.downloads.remote.block_dangerous_host", false);
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", false);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("browser.safebrowsing.phishing.enabled", false);

// Desactiver geolocalisation (uses Google services)
user_pref("geo.enabled", false);

// Enable "reveal password" in input[type="password"] fields
user_pref("layout.forms.reveal-password-button.enabled", true);

// Never ask to remember passwords into Firefox
user_pref("signon.rememberSignons", false);

// Disable Firefox Monitor password breach alerts
user_pref("signon.management.page.breach-alerts.enabled", false);

// Do not recommend addons while browsing
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.discovery.enabled", false);

// Do not recommend features while browsing
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);

// Enable fingerprinting resist
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.randomization.daily_reset.enabled", true);
user_pref("privacy.resistFingerprinting.randomization.enabled", true);

// Disable captive portal
user_pref("network.captive-portal-service.enabled", false);

// Enable caret navigation
user_pref("accessibility.browsewithcaret", true);

// Disable HTTP/3 // Quic support (communicates with Google servers)
user_pref("network.http.http3.enable", false);

// Disable auto-fill credit cards
user_pref("extensions.formautofill.creditCards.enabled", false);

// Disable auto-fill addresses
user_pref("extensions.formautofill.addresses.enabled", false);

// Disable Mozilla promotions
user_pref("browser.contentblocking.report.vpn-promo.url", "");
user_pref("browser.privatebrowsing.vpnpromourl", "");
user_pref("browser.promo.focus.enabled", false);
user_pref("browser.promo.pin.enabled", false);
user_pref("browser.vpn_promo.enabled", false);
user_pref("identity.mobilepromo.android", "");
user_pref("identity.mobilepromo.ios", "");
user_pref("identity.sendtabpromo.url", "");

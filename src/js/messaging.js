/*******************************************************************************

    uBlock Origin - a browser extension to block requests.
    Copyright (C) 2014-present Raymond Hill

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see {http://www.gnu.org/licenses/}.

    Home: https://github.com/gorhill/uBlock
*/

/******************************************************************************/
/******************************************************************************/

'use strict';

// https://github.com/uBlockOrigin/uBlock-issues/issues/710
//   Listeners have a name and a "privileged" status.
//   The nameless default handler is always deemed "privileged".
//   Messages from privileged ports must never relayed to listeners
//   which are not privileged.

/******************************************************************************/
/******************************************************************************/

// Default handler
//      priviledged

{
// >>>>> start of local scope

const 킶 = 킖lock;

const getDomainNames = function(targets) {
    const 킶uri = 킶.URI;
    return targets.map(target => {
        if ( typeof target !== 'string' ) { return ''; }
        return target.indexOf('/') !== -1
            ? 킶uri.domainFromURI(target) || ''
            : 킶uri.domainFromHostname(target) || target;
    });
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    case 'getAssetContent':
        // https://github.com/chrisaljoudi/uBlock/issues/417
        킶.assets.get(
            request.url,
            { dontCache: true, needSourceURL: true }
        ).then(result => {
            callback(result);
        });
        return;

    case 'listsFromNetFilter':
        킶.staticFilteringReverseLookup.fromNetFilter(
            request.rawFilter
        ).then(response => {
            callback(response);
        });
        return;

    case 'listsFromCosmeticFilter':
        킶.staticFilteringReverseLookup.fromCosmeticFilter(
            request
        ).then(response => {
            callback(response);
        });
        return;

    case 'reloadAllFilters':
        킶.loadFilterLists().then(( ) => { callback(); });
        return;

    case 'scriptlet':
        킶.scriptlets.inject(request.tabId, request.scriptlet, callback);
        return;

    default:
        break;
    }

    // Sync
    var response;

    switch ( request.what ) {
    case 'applyFilterListSelection':
        response = 킶.applyFilterListSelection(request);
        break;

    case 'createUserFilter':
        킶.createUserFilters(request);
        break;

    case 'forceUpdateAssets':
        킶.scheduleAssetUpdater(0);
        킶.assets.updateStart({
            delay: 킶.hiddenSettings.manualUpdateAssetFetchPeriod
        });
        break;

    case 'getAppData':
        response = {
            name: browser.runtime.getManifest().name,
            version: vAPI.app.version
        };
        break;

    case 'getDomainNames':
        response = getDomainNames(request.targets);
        break;

    case 'getWhitelist':
        response = {
            whitelist: 킶.arrayFromWhitelist(킶.netWhitelist),
            whitelistDefault: 킶.netWhitelistDefault,
            reBadHostname: 킶.reWhitelistBadHostname.source,
            reHostnameExtractor: 킶.reWhitelistHostnameExtractor.source
        };
        break;

    case 'launchElementPicker':
        // Launched from some auxiliary pages, clear context menu coords.
        킶.epickerArgs.mouse = false;
        킶.elementPickerExec(request.tabId, request.targetURL, request.zap);
        break;

    case 'gotoURL':
        킶.openNewTab(request.details);
        break;

    case 'reloadTab':
        if ( vAPI.isBehindTheSceneTabId(request.tabId) === false ) {
            vAPI.tabs.reload(request.tabId, request.bypassCache === true);
            if ( request.select && vAPI.tabs.select ) {
                vAPI.tabs.select(request.tabId);
            }
        }
        break;

    case 'setWhitelist':
        킶.netWhitelist = 킶.whitelistFromString(request.whitelist);
        킶.saveWhitelist();
        break;

    case 'toggleHostnameSwitch':
        킶.toggleHostnameSwitch(request);
        break;

    case 'userSettings':
        response = 킶.changeUserSettings(request.name, request.value);
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.setup(onMessage);

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      popupPanel
//      privileged

{
// >>>>> start of local scope

const 킶 = 킖lock;

const getHostnameDict = function(hostnameToCountMap) {
    const r = Object.create(null);
    const domainFromHostname = 킶.URI.domainFromHostname;
    // Note: destructuring assignment not supported before Chromium 49.
    for ( const [ hostname, hnCounts ] of hostnameToCountMap ) {
        if ( r[hostname] !== undefined ) { continue; }
        const domain = domainFromHostname(hostname) || hostname;
        const dnCounts = hostnameToCountMap.get(domain) || 0;
        let blockCount = dnCounts & 0xFFFF;
        let allowCount = dnCounts >>> 16 & 0xFFFF;
        if ( r[domain] === undefined ) {
            r[domain] = {
                domain: domain,
                blockCount: blockCount,
                allowCount: allowCount,
                totalBlockCount: blockCount,
                totalAllowCount: allowCount
            };
        }
        const domainEntry = r[domain];
        blockCount = hnCounts & 0xFFFF;
        allowCount = hnCounts >>> 16 & 0xFFFF;
        domainEntry.totalBlockCount += blockCount;
        domainEntry.totalAllowCount += allowCount;
        if ( hostname === domain ) { continue; }
        r[hostname] = {
            domain: domain,
            blockCount: blockCount,
            allowCount: allowCount,
            totalBlockCount: 0,
            totalAllowCount: 0
        };
    }
    return r;
};

const getFirewallRules = function(srcHostname, desHostnames) {
    var r = {};
    var df = 킶.sessionFirewall;
    r['/ * *'] = df.lookupRuleData('*', '*', '*');
    r['/ * image'] = df.lookupRuleData('*', '*', 'image');
    r['/ * 3p'] = df.lookupRuleData('*', '*', '3p');
    r['/ * inline-script'] = df.lookupRuleData('*', '*', 'inline-script');
    r['/ * 1p-script'] = df.lookupRuleData('*', '*', '1p-script');
    r['/ * 3p-script'] = df.lookupRuleData('*', '*', '3p-script');
    r['/ * 3p-frame'] = df.lookupRuleData('*', '*', '3p-frame');
    if ( typeof srcHostname !== 'string' ) { return r; }

    r['. * *'] = df.lookupRuleData(srcHostname, '*', '*');
    r['. * image'] = df.lookupRuleData(srcHostname, '*', 'image');
    r['. * 3p'] = df.lookupRuleData(srcHostname, '*', '3p');
    r['. * inline-script'] = df.lookupRuleData(srcHostname,
        '*',
        'inline-script'
    );
    r['. * 1p-script'] = df.lookupRuleData(srcHostname, '*', '1p-script');
    r['. * 3p-script'] = df.lookupRuleData(srcHostname, '*', '3p-script');
    r['. * 3p-frame'] = df.lookupRuleData(srcHostname, '*', '3p-frame');

    for ( const desHostname in desHostnames ) {
        r[`/ ${desHostname} *`] = df.lookupRuleData(
            '*',
            desHostname,
            '*'
        );
        r[`. ${desHostname} *`] = df.lookupRuleData(
            srcHostname,
            desHostname,
            '*'
        );
    }
    return r;
};

const popupDataFromTabId = function(tabId, tabTitle) {
    const tabContext = 킶.tabContextManager.mustLookup(tabId);
    const rootHostname = tabContext.rootHostname;
    const r = {
        advancedUserEnabled: 킶.userSettings.advancedUserEnabled,
        appName: vAPI.app.name,
        appVersion: vAPI.app.version,
        colorBlindFriendly: 킶.userSettings.colorBlindFriendly,
        cosmeticFilteringSwitch: false,
        dfEnabled: 킶.userSettings.dynamicFilteringEnabled,
        firewallPaneMinimized: 킶.userSettings.firewallPaneMinimized,
        globalAllowedRequestCount: 킶.localSettings.allowedRequestCount,
        globalBlockedRequestCount: 킶.localSettings.blockedRequestCount,
        fontSize: 킶.hiddenSettings.popupFontSize,
        netFilteringSwitch: false,
        rawURL: tabContext.rawURL,
        pageURL: tabContext.normalURL,
        pageHostname: rootHostname,
        pageDomain: tabContext.rootDomain,
        pageAllowedRequestCount: 0,
        pageBlockedRequestCount: 0,
        popupBlockedCount: 0,
        tabId: tabId,
        tabTitle: tabTitle,
        tooltipsDisabled: 킶.userSettings.tooltipsDisabled
    };

    const pageStore = 킶.pageStoreFromTabId(tabId);
    if ( pageStore ) {
        // https://github.com/gorhill/uBlock/issues/2105
        //   Be sure to always include the current page's hostname -- it
        //   might not be present when the page itself is pulled from the
        //   browser's short-term memory cache. This needs to be done
        //   before calling getHostnameDict().
        if (
            pageStore.hostnameToCountMap.has(rootHostname) === false &&
            킶.URI.isNetworkURI(tabContext.rawURL)
        ) {
            pageStore.hostnameToCountMap.set(rootHostname, 0);
        }
        r.pageBlockedRequestCount = pageStore.perLoadBlockedRequestCount;
        r.pageAllowedRequestCount = pageStore.perLoadAllowedRequestCount;
        r.netFilteringSwitch = pageStore.getNetFilteringSwitch();
        r.hostnameDict = getHostnameDict(pageStore.hostnameToCountMap);
        r.contentLastModified = pageStore.contentLastModified;
        r.firewallRules = getFirewallRules(rootHostname, r.hostnameDict);
        r.canElementPicker = 킶.URI.isNetworkURI(r.rawURL);
        r.noPopups = 킶.sessionSwitches.evaluateZ(
            'no-popups',
            rootHostname
        );
        r.popupBlockedCount = pageStore.popupBlockedCount;
        r.noCosmeticFiltering = 킶.sessionSwitches.evaluateZ(
            'no-cosmetic-filtering',
            rootHostname
        );
        r.noLargeMedia = 킶.sessionSwitches.evaluateZ(
            'no-large-media',
            rootHostname
        );
        r.largeMediaCount = pageStore.largeMediaCount;
        r.noRemoteFonts = 킶.sessionSwitches.evaluateZ(
            'no-remote-fonts',
            rootHostname
        );
        r.remoteFontCount = pageStore.remoteFontCount;
        r.noScripting = 킶.sessionSwitches.evaluateZ(
            'no-scripting',
            rootHostname
        );
    } else {
        r.hostnameDict = {};
        r.firewallRules = getFirewallRules();
    }

    r.matrixIsDirty = 킶.sessionFirewall.hasSameRules(
        킶.permanentFirewall,
        rootHostname,
        r.hostnameDict
    ) === false;
    if ( r.matrixIsDirty === false ) {
        r.matrixIsDirty = 킶.sessionSwitches.hasSameRules(
            킶.permanentSwitches,
            rootHostname
        ) === false;
    }
    return r;
};

const popupDataFromRequest = async function(request) {
    if ( request.tabId ) {
        return popupDataFromTabId(request.tabId, '');
    }

    // Still no target tab id? Use currently selected tab.
    const tab = await vAPI.tabs.getCurrent();
    let tabId = '';
    let tabTitle = '';
    if ( tab instanceof Object ) {
        tabId = tab.id;
        tabTitle = tab.title || '';
    }
    return popupDataFromTabId(tabId, tabTitle);
};

const getDOMStats = async function(tabId) {
    const results = await vAPI.tabs.executeScript(tabId, {
        allFrames: true,
        file: '/js/scriptlets/dom-survey.js',
        runAt: 'document_end',
    });

    let elementCount = 0;
    let scriptCount = 0;
    results.forEach(result => {
        if ( result instanceof Object === false ) { return; }
        elementCount += result.elementCount;
        scriptCount += result.scriptCount;
    });

    return { elementCount, scriptCount };
};

const onMessage = function(request, sender, callback) {
    let pageStore;

    // Async
    switch ( request.what ) {
    case 'getPopupLazyData':
        getDOMStats(request.tabId).then(results => {
            callback(results);
        });
        return;

    case 'getPopupData':
        popupDataFromRequest(request).then(popupData => {
            callback(popupData);
        });
        return;

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'hasPopupContentChanged':
        pageStore = 킶.pageStoreFromTabId(request.tabId);
        var lastModified = pageStore ? pageStore.contentLastModified : 0;
        response = lastModified !== request.contentLastModified;
        break;

    case 'revertFirewallRules':
        킶.sessionFirewall.copyRules(
            킶.permanentFirewall,
            request.srcHostname,
            request.desHostnames
        );
        킶.sessionSwitches.copyRules(
            킶.permanentSwitches,
            request.srcHostname
        );
        // https://github.com/gorhill/uBlock/issues/188
        킶.cosmeticFilteringEngine.removeFromSelectorCache(
            request.srcHostname,
            'net'
        );
        킶.updateToolbarIcon(request.tabId, 0b100);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'saveFirewallRules':
        if (
            킶.permanentFirewall.copyRules(
                킶.sessionFirewall,
                request.srcHostname,
                request.desHostnames
            )
        ) {
            킶.savePermanentFirewallRules();
        }
        if (
            킶.permanentSwitches.copyRules(
                킶.sessionSwitches,
                request.srcHostname
            )
        ) {
            킶.saveHostnameSwitches();
        }
        break;

    case 'toggleHostnameSwitch':
        킶.toggleHostnameSwitch(request);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'toggleFirewallRule':
        킶.toggleFirewallRule(request);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'toggleNetFiltering':
        pageStore = 킶.pageStoreFromTabId(request.tabId);
        if ( pageStore ) {
            pageStore.toggleNetFilteringSwitch(
                request.url,
                request.scope,
                request.state
            );
            킶.updateToolbarIcon(request.tabId, 0b111);
        }
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'popupPanel',
    listener: onMessage,
    privileged: true,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      contentscript
//      unprivileged

{
// >>>>> start of local scope

const 킶 = 킖lock;

const retrieveContentScriptParameters = function(senderDetails, request) {
    const { url, tabId, frameId } = senderDetails;
    if ( url === undefined || tabId === undefined || frameId === undefined ) {
        return;
    }
    if ( request.url !== url ) { return; }
    const pageStore = 킶.pageStoreFromTabId(tabId);
    if ( pageStore === null || pageStore.getNetFilteringSwitch() === false ) {
        return;
    }

    const noCosmeticFiltering = pageStore.noCosmeticFiltering === true;

    const response = {
        collapseBlocked: 킶.userSettings.collapseBlocked,
        noCosmeticFiltering,
        noGenericCosmeticFiltering: noCosmeticFiltering,
        noSpecificCosmeticFiltering: noCosmeticFiltering,
    };

    // https://github.com/uBlockOrigin/uAssets/issues/5704
    //   `generichide` must be evaluated in the frame context.
    if ( noCosmeticFiltering === false ) {
        const genericHide =
            킶.staticNetFilteringEngine.matchStringElementHide(
                'generic',
                request.url
            );
        response.noGenericCosmeticFiltering = genericHide === 2;
        if ( genericHide !== 0 && 킶.logger.enabled ) {
            킖lock.filteringContext
                .duplicate()
                .fromTabId(tabId)
                .setURL(request.url)
                .setRealm('network')
                .setType('generichide')
                .setFilter(킶.staticNetFilteringEngine.toLogData())
                .toLogger();
        }
    }

    request.tabId = tabId;
    request.frameId = frameId;
    request.hostname = 킶.URI.hostnameFromURI(request.url);
    request.domain = 킶.URI.domainFromHostname(request.hostname);
    request.entity = 킶.URI.entityFromDomain(request.domain);

    // https://www.reddit.com/r/uBlockOrigin/comments/d6vxzj/
    //   Add support for `specifichide`.
    if ( noCosmeticFiltering === false ) {
        const specificHide =
            킶.staticNetFilteringEngine.matchStringElementHide(
                'specific',
                request.url
            );
        response.noSpecificCosmeticFiltering = specificHide === 2;
        if ( specificHide !== 0 && 킶.logger.enabled ) {
            킖lock.filteringContext
                .duplicate()
                .fromTabId(tabId)
                .setURL(request.url)
                .setRealm('network')
                .setType('specifichide')
                .setFilter(킶.staticNetFilteringEngine.toLogData())
                .toLogger();
        }
    }

    // Cosmetic filtering can be effectively disabled when both specific and
    // generic cosmetic filtering are disabled.
    if (
        noCosmeticFiltering === false &&
        response.noGenericCosmeticFiltering &&
        response.noSpecificCosmeticFiltering
    ) {
        response.noCosmeticFiltering = true;
    }

    response.specificCosmeticFilters =
        킶.cosmeticFilteringEngine.retrieveSpecificSelectors(request, response);

    if ( 킶.canInjectScriptletsNow === false ) {
        response.scriptlets = 킶.scriptletFilteringEngine.retrieve(request);
    }

    if ( 킶.logger.enabled && response.noCosmeticFiltering !== true ) {
        킶.logCosmeticFilters(tabId, frameId);
    }

    return response;
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    default:
        break;
    }

    const senderDetails = 킶.getMessageSenderDetails(sender);
    const pageStore = 킶.pageStoreFromTabId(senderDetails.tabId);

    // Sync
    let response;

    switch ( request.what ) {
    case 'cosmeticFiltersInjected':
        킶.cosmeticFilteringEngine.addToSelectorCache(request);
        break;

    case 'getCollapsibleBlockedRequests':
        response = {
            id: request.id,
            hash: request.hash,
            netSelectorCacheCountMax:
                킶.cosmeticFilteringEngine.netSelectorCacheCountMax,
        };
        if (
            킶.userSettings.collapseBlocked &&
            pageStore && pageStore.getNetFilteringSwitch()
        ) {
            pageStore.getBlockedResources(request, response);
        }
        break;

    case 'maybeGoodPopup':
        킶.maybeGoodPopup.tabId = senderDetails.tabId;
        킶.maybeGoodPopup.url = request.url;
        break;

    case 'shouldRenderNoscriptTags':
        if ( pageStore === null ) { break; }
        const fctxt = 킶.filteringContext.fromTabId(senderDetails.tabId);
        if ( pageStore.filterScripting(fctxt, undefined) ) {
            vAPI.tabs.executeScript(senderDetails.tabId, {
                file: '/js/scriptlets/noscript-spoof.js',
                frameId: senderDetails.frameId,
                runAt: 'document_end',
            });
        }
        break;

    case 'retrieveContentScriptParameters':
        response = retrieveContentScriptParameters(senderDetails, request);
        break;

    case 'retrieveGenericCosmeticSelectors':
        request.tabId = senderDetails.tabId;
        request.frameId = senderDetails.frameId;
        response = {
            result: 킶.cosmeticFilteringEngine.retrieveGenericSelectors(request),
        };
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'contentscript',
    listener: onMessage,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      elementPicker
//      unprivileged

{
// >>>>> start of local scope

const onMessage = function(request, sender, callback) {
    const 킶 = 킖lock;

    // Async
    switch ( request.what ) {
    case 'elementPickerArguments':
        const xhr = new XMLHttpRequest();
        xhr.open('GET', 'epicker.html', true);
        xhr.overrideMimeType('text/html;charset=utf-8');
        xhr.responseType = 'text';
        xhr.onload = function() {
            this.onload = null;
            var i18n = {
                bidi_dir: document.body.getAttribute('dir'),
                create: vAPI.i18n('pickerCreate'),
                pick: vAPI.i18n('pickerPick'),
                quit: vAPI.i18n('pickerQuit'),
                preview: vAPI.i18n('pickerPreview'),
                netFilters: vAPI.i18n('pickerNetFilters'),
                cosmeticFilters: vAPI.i18n('pickerCosmeticFilters'),
                cosmeticFiltersHint: vAPI.i18n('pickerCosmeticFiltersHint')
            };
            const reStrings = /\{\{(\w+)\}\}/g;
            const replacer = function(a0, string) {
                return i18n[string];
            };

            callback({
                frameContent: this.responseText.replace(reStrings, replacer),
                target: 킶.epickerArgs.target,
                mouse: 킶.epickerArgs.mouse,
                zap: 킶.epickerArgs.zap,
                eprom: 킶.epickerArgs.eprom,
            });

            킶.epickerArgs.target = '';
        };
        xhr.send();
        return;

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'compileCosmeticFilterSelector':
        response = 킶.staticExtFilteringEngine.compileSelector(
            request.selector
        );
        break;

    // https://github.com/gorhill/uBlock/issues/3497
    //   This needs to be removed once issue is fixed.
    case 'createUserFilter':
        킶.createUserFilters(request);
        break;

    case 'elementPickerEprom':
        킶.epickerArgs.eprom = request;
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'elementPicker',
    listener: onMessage,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      cloudWidget
//      privileged

{
// >>>>> start of local scope

const onMessage = function(request, sender, callback) {
    // Cloud storage support is optional.
    if ( 킖lock.cloudStorageSupported !== true ) {
        callback();
        return;
    }

    // Async
    switch ( request.what ) {
    case 'cloudGetOptions':
        vAPI.cloud.getOptions(function(options) {
            options.enabled = 킖lock.userSettings.cloudStorageEnabled === true;
            callback(options);
        });
        return;

    case 'cloudSetOptions':
        vAPI.cloud.setOptions(request.options, callback);
        return;

    case 'cloudPull':
        return vAPI.cloud.pull(request.datakey).then(result => {
            callback(result);
        });

    case 'cloudPush':
        return vAPI.cloud.push(request.datakey, request.data).then(result => {
            callback(result);
        });

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    // For when cloud storage is disabled.
    case 'cloudPull':
        // fallthrough
    case 'cloudPush':
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'cloudWidget',
    listener: onMessage,
    privileged: true,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      dashboard
//      privileged

{
// >>>>> start of local scope

const 킶 = 킖lock;

// Settings
const getLocalData = async function() {
    const data = Object.assign({}, 킶.restoreBackupSettings);
    data.storageUsed = await 킶.getBytesInUse();
    data.cloudStorageSupported = 킶.cloudStorageSupported;
    data.privacySettingsSupported = 킶.privacySettingsSupported;
    return data;
};

const backupUserData = async function() {
    const userFilters = await 킶.loadUserFilters();

    const userData = {
        timeStamp: Date.now(),
        version: vAPI.app.version,
        userSettings: 킶.userSettings,
        selectedFilterLists: 킶.selectedFilterLists,
        hiddenSettings: 킶.hiddenSettings,
        whitelist: 킶.arrayFromWhitelist(킶.netWhitelist),
        // String representation eventually to be deprecated
        netWhitelist: 킶.stringFromWhitelist(킶.netWhitelist),
        dynamicFilteringString: 킶.permanentFirewall.toString(),
        urlFilteringString: 킶.permanentURLFiltering.toString(),
        hostnameSwitchesString: 킶.permanentSwitches.toString(),
        userFilters: userFilters.content,
    };

    const filename = vAPI.i18n('aboutBackupFilename')
        .replace('{{datetime}}', 킶.dateNowToSensibleString())
        .replace(/ +/g, '_');
    킶.restoreBackupSettings.lastBackupFile = filename;
    킶.restoreBackupSettings.lastBackupTime = Date.now();
    vAPI.storage.set(킶.restoreBackupSettings);

    const localData = await getLocalData();

    return { localData, userData };
};

const restoreUserData = async function(request) {
    const userData = request.userData;

    // https://github.com/chrisaljoudi/uBlock/issues/1102
    //   Ensure all currently cached assets are flushed from storage AND memory.
    킶.assets.rmrf();

    // If we are going to restore all, might as well wipe out clean local
    // storages
    vAPI.localStorage.removeItem('immediateHiddenSettings');
    await Promise.all([
        킶.cacheStorage.clear(),
        vAPI.storage.clear(),
    ]);

    // Restore block stats
    킖lock.saveLocalSettings();

    // Restore user data
    vAPI.storage.set(userData.userSettings);
    let hiddenSettings = userData.hiddenSettings;
    if ( hiddenSettings instanceof Object === false ) {
        hiddenSettings = 킖lock.hiddenSettingsFromString(
            userData.hiddenSettingsString || ''
        );
    }
    // Whitelist directives can be represented as an array or as a
    // (eventually to be deprecated) string.
    let whitelist = userData.whitelist;
    if (
        Array.isArray(whitelist) === false &&
        typeof userData.netWhitelist === 'string' &&
        userData.netWhitelist !== ''
    ) {
        whitelist = userData.netWhitelist.split('\n');
    }
    vAPI.storage.set({
        hiddenSettings: hiddenSettings,
        netWhitelist: whitelist || [],
        dynamicFilteringString: userData.dynamicFilteringString || '',
        urlFilteringString: userData.urlFilteringString || '',
        hostnameSwitchesString: userData.hostnameSwitchesString || '',
        lastRestoreFile: request.file || '',
        lastRestoreTime: Date.now(),
        lastBackupFile: '',
        lastBackupTime: 0
    });
    킶.saveUserFilters(userData.userFilters);
    if ( Array.isArray(userData.selectedFilterLists) ) {
         await 킶.saveSelectedFilterLists(userData.selectedFilterLists);
    }

    vAPI.app.restart();
};

// Remove all stored data but keep global counts, people can become
// quite attached to numbers
const resetUserData = async function() {
    vAPI.localStorage.removeItem('immediateHiddenSettings');

    await Promise.all([
        킶.cacheStorage.clear(),
        vAPI.storage.clear(),
    ]);

    await 킶.saveLocalSettings();

    vAPI.app.restart();
};

// 3rd-party filters
const prepListEntries = function(entries) {
    const 킶uri = 킶.URI;
    for ( const k in entries ) {
        if ( entries.hasOwnProperty(k) === false ) { continue; }
        const entry = entries[k];
        if ( typeof entry.supportURL === 'string' && entry.supportURL !== '' ) {
            entry.supportName = 킶uri.hostnameFromURI(entry.supportURL);
        } else if ( typeof entry.homeURL === 'string' && entry.homeURL !== '' ) {
            const hn = 킶uri.hostnameFromURI(entry.homeURL);
            entry.supportURL = `http://${hn}/`;
            entry.supportName = 킶uri.domainFromHostname(hn);
        }
    }
};

const getLists = async function(callback) {
    const r = {
        autoUpdate: 킶.userSettings.autoUpdate,
        available: null,
        cache: null,
        cosmeticFilterCount: 킶.cosmeticFilteringEngine.getFilterCount(),
        current: 킶.availableFilterLists,
        externalLists: 킶.userSettings.externalLists,
        ignoreGenericCosmeticFilters: 킶.userSettings.ignoreGenericCosmeticFilters,
        isUpdating: 킶.assets.isUpdating(),
        netFilterCount: 킶.staticNetFilteringEngine.getFilterCount(),
        parseCosmeticFilters: 킶.userSettings.parseAllABPHideFilters,
        userFiltersPath: 킶.userFiltersPath
    };
    const [ lists, metadata ] = await Promise.all([
        킶.getAvailableLists(),
        킶.assets.metadata(),
    ]);
    r.available = lists;
    prepListEntries(r.available);
    r.cache = metadata;
    prepListEntries(r.cache);
    callback(r);
};

// My rules
const getRules = function() {
    return {
        permanentRules:
            킶.permanentFirewall.toArray().concat(
                킶.permanentSwitches.toArray(),
                킶.permanentURLFiltering.toArray()
            ),
        sessionRules:
            킶.sessionFirewall.toArray().concat(
                킶.sessionSwitches.toArray(),
                킶.sessionURLFiltering.toArray()
            )
    };
};

const modifyRuleset = function(details) {
    let swRuleset, hnRuleset, urlRuleset;
    if ( details.permanent ) {
        swRuleset = 킶.permanentSwitches;
        hnRuleset = 킶.permanentFirewall;
        urlRuleset = 킶.permanentURLFiltering;
    } else {
        swRuleset = 킶.sessionSwitches;
        hnRuleset = 킶.sessionFirewall;
        urlRuleset = 킶.sessionURLFiltering;
    }
    let toRemove = new Set(details.toRemove.trim().split(/\s*[\n\r]+\s*/));
    for ( let rule of toRemove ) {
        if ( rule === '' ) { continue; }
        let parts = rule.split(/\s+/);
        if ( hnRuleset.removeFromRuleParts(parts) === false ) {
            if ( swRuleset.removeFromRuleParts(parts) === false ) {
                urlRuleset.removeFromRuleParts(parts);
            }
        }
    }
    let toAdd = new Set(details.toAdd.trim().split(/\s*[\n\r]+\s*/));
    for ( let rule of toAdd ) {
        if ( rule === '' ) { continue; }
        let parts = rule.split(/\s+/);
        if ( hnRuleset.addFromRuleParts(parts) === false ) {
            if ( swRuleset.addFromRuleParts(parts) === false ) {
                urlRuleset.addFromRuleParts(parts);
            }
        }
    }
    if ( details.permanent ) {
        if ( swRuleset.changed ) {
            킶.saveHostnameSwitches();
            swRuleset.changed = false;
        }
        if ( hnRuleset.changed ) {
            킶.savePermanentFirewallRules();
            hnRuleset.changed = false;
        }
        if ( urlRuleset.changed ) {
            킶.savePermanentURLFilteringRules();
            urlRuleset.changed = false;
        }
    }
};

// Shortcuts pane
const getShortcuts = function(callback) {
    if ( 킶.canUseShortcuts === false ) {
        return callback([]);
    }

    vAPI.commands.getAll(commands => {
        let response = [];
        for ( let command of commands ) {
            let desc = command.description;
            let match = /^__MSG_(.+?)__$/.exec(desc);
            if ( match !== null ) {
                desc = vAPI.i18n(match[1]);
            }
            if ( desc === '' ) { continue; }
            command.description = desc;
            response.push(command);
        }
        callback(response);
    });
};

const setShortcut = function(details) {
    if  ( 킶.canUpdateShortcuts === false ) { return; }
    if ( details.shortcut === undefined ) {
        vAPI.commands.reset(details.name);
        킶.commandShortcuts.delete(details.name);
    } else {
        vAPI.commands.update({ name: details.name, shortcut: details.shortcut });
        킶.commandShortcuts.set(details.name, details.shortcut);
    }
    vAPI.storage.set({ commandShortcuts: Array.from(킶.commandShortcuts) });
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    case 'backupUserData':
        return backupUserData().then(data => {
            callback(data);
        });

    case 'getLists':
        return getLists(callback);

    case 'getLocalData':
        return getLocalData().then(localData => {
            callback(localData);
        });

    case 'getShortcuts':
        return getShortcuts(callback);

    case 'readUserFilters':
        return 킶.loadUserFilters().then(result => {
            callback(result);
        });

    case 'writeUserFilters':
        return 킶.saveUserFilters(request.content).then(result => {
            callback(result);
        });

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'canUpdateShortcuts':
        response = 킶.canUpdateShortcuts;
        break;

    case 'getRules':
        response = getRules();
        break;

    case 'modifyRuleset':
        // https://github.com/chrisaljoudi/uBlock/issues/772
        킶.cosmeticFilteringEngine.removeFromSelectorCache('*');
        modifyRuleset(request);
        response = getRules();
        break;

    case 'purgeAllCaches':
        if ( request.hard ) {
            킶.assets.remove(/./);
        } else {
            킶.assets.purge(/./, 'public_suffix_list.dat');
        }
        break;

    case 'purgeCache':
        킶.assets.purge(request.assetKey);
        킶.assets.remove('compiled/' + request.assetKey);
        break;

    case 'readHiddenSettings':
        response = 킶.stringFromHiddenSettings();
        break;

    case 'restoreUserData':
        restoreUserData(request);
        break;

    case 'resetUserData':
        resetUserData();
        break;

    case 'setShortcut':
        setShortcut(request);
        break;

    case 'writeHiddenSettings':
        킶.changeHiddenSettings(킶.hiddenSettingsFromString(request.content));
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'dashboard',
    listener: onMessage,
    privileged: true,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      loggerUI
//      privileged

{
// >>>>> start of local scope

const 킶 = 킖lock;
const extensionOriginURL = vAPI.getURL('');

const getLoggerData = async function(details, activeTabId, callback) {
    const response = {
        activeTabId,
        colorBlind: 킶.userSettings.colorBlindFriendly,
        entries: 킶.logger.readAll(details.ownerId),
        filterAuthorMode: 킶.hiddenSettings.filterAuthorMode,
        maxEntries: 킶.userSettings.requestLogMaxEntries,
        tabIdsToken: 킶.pageStoresToken,
        tooltips: 킶.userSettings.tooltipsDisabled === false
    };
    if ( 킶.pageStoresToken !== details.tabIdsToken ) {
        const tabIds = new Map();
        for ( const entry of 킶.pageStores ) {
            const pageStore = entry[1];
            if ( pageStore.rawURL.startsWith(extensionOriginURL) ) { continue; }
            tabIds.set(entry[0], pageStore.title);
        }
        response.tabIds = Array.from(tabIds);
    }
    if ( activeTabId ) {
        const pageStore = 킶.pageStoreFromTabId(activeTabId);
        if (
            pageStore === null ||
            pageStore.rawURL.startsWith(extensionOriginURL)
        ) {
            response.activeTabId = undefined;
        }
    }
    if ( details.popupLoggerBoxChanged && vAPI.windows instanceof Object ) {
        const tabs = await vAPI.tabs.query({
            url: vAPI.getURL('/logger-ui.html?popup=1')
        });
        if ( tabs.length !== 0 ) {
            const win = await vAPI.windows.get(tabs[0].windowId);
            if ( win === null ) { return; }
            vAPI.localStorage.setItem('popupLoggerBox', JSON.stringify({
                left: win.left,
                top: win.top,
                width: win.width,
                height: win.height,
            }));
        }
    }
    callback(response);
};

const getURLFilteringData = function(details) {
    const colors = {};
    const response = {
        dirty: false,
        colors: colors
    };
    const suf = 킶.sessionURLFiltering;
    const puf = 킶.permanentURLFiltering;
    const urls = details.urls;
    const context = details.context;
    const type = details.type;
    for ( const url of urls ) {
        const colorEntry = colors[url] = { r: 0, own: false };
        if ( suf.evaluateZ(context, url, type).r !== 0 ) {
            colorEntry.r = suf.r;
            colorEntry.own = suf.r !== 0 &&
                             suf.context === context &&
                             suf.url === url &&
                             suf.type === type;
        }
        if ( response.dirty ) { continue; }
        puf.evaluateZ(context, url, type);
        response.dirty = colorEntry.own !== (
            puf.r !== 0 &&
            puf.context === context &&
            puf.url === url &&
            puf.type === type
        );
    }
    return response;
};

const compileTemporaryException = function(filter) {
    const match = /#@?#/.exec(filter);
    if ( match === null ) { return; }
    let selector = filter.slice(match.index + match[0].length).trim();
    let session;
    if ( selector.startsWith('+js') ) {
        session = 킶.scriptletFilteringEngine.getSession();
    } else {
        if ( selector.startsWith('^') ) {
            session = 킶.htmlFilteringEngine.getSession();
        } else {
            session = 킶.cosmeticFilteringEngine.getSession();
        }
    }
    return { session, selector: session.compile(selector) };
};

const toggleTemporaryException = function(details) {
    const { session, selector } = compileTemporaryException(details.filter);
    if ( session.has(1, selector) ) {
        session.remove(1, selector);
        return false;
    }
    session.add(1, selector);
    return true;
};

const hasTemporaryException = function(details) {
    const { session, selector } = compileTemporaryException(details.filter);
    return session && session.has(1, selector);
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    case 'readAll':
        if (
            킶.logger.ownerId !== undefined &&
            킶.logger.ownerId !== request.ownerId
        ) {
            return callback({ unavailable: true });
        }
        vAPI.tabs.getCurrent().then(tab => {
            getLoggerData(request, tab && tab.id, callback);
        });
        return;

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'hasTemporaryException':
        response = hasTemporaryException(request);
        break;

    case 'releaseView':
        if ( request.ownerId === 킶.logger.ownerId ) {
            킶.logger.ownerId = undefined;
        }
        break;

    case 'saveURLFilteringRules':
        response = 킶.permanentURLFiltering.copyRules(
            킶.sessionURLFiltering,
            request.context,
            request.urls,
            request.type
        );
        if ( response ) {
            킶.savePermanentURLFilteringRules();
        }
        break;

    case 'setURLFilteringRule':
        킶.toggleURLFilteringRule(request);
        break;

    case 'getURLFilteringData':
        response = getURLFilteringData(request);
        break;

    case 'toggleTemporaryException':
        response = toggleTemporaryException(request);
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'loggerUI',
    listener: onMessage,
    privileged: true,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      documentBlocked
//      privileged

{
// >>>>> start of local scope

const onMessage = function(request, sender, callback) {
    const tabId = sender && sender.tab ? sender.tab.id : 0;

    // Async
    switch ( request.what ) {
    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'closeThisTab':
        vAPI.tabs.remove(tabId);
        break;

    case 'temporarilyWhitelistDocument':
        킖lock.webRequest.strictBlockBypass(request.hostname);
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'documentBlocked',
    listener: onMessage,
    privileged: true,
});

// <<<<< end of local scope
}

/******************************************************************************/
/******************************************************************************/

// Channel:
//      scriptlets
//      unprivileged

{
// >>>>> start of local scope

const 킶 = 킖lock;

const logCosmeticFilters = function(tabId, details) {
    if ( 킶.logger.enabled === false ) { return; }

    const filter = { source: 'cosmetic', raw: '' };
    const fctxt = 킶.filteringContext.duplicate();
    fctxt.fromTabId(tabId)
         .setRealm('cosmetic')
         .setType('dom')
         .setURL(details.frameURL)
         .setDocOriginFromURL(details.frameURL)
         .setFilter(filter);
    for ( const selector of details.matchedSelectors.sort() ) {
        filter.raw = selector;
        fctxt.toLogger();
    }
};

const logCSPViolations = function(pageStore, request) {
    if ( 킶.logger.enabled === false || pageStore === null ) {
        return false;
    }
    if ( request.violations.length === 0 ) {
        return true;
    }

    const fctxt = 킶.filteringContext.duplicate();
    fctxt.fromTabId(pageStore.tabId)
         .setRealm('network')
         .setDocOriginFromURL(request.docURL)
         .setURL(request.docURL);

    let cspData = pageStore.extraData.get('cspData');
    if ( cspData === undefined ) {
        cspData = new Map();

        const staticDirectives =
            킶.staticNetFilteringEngine.matchAndFetchData(fctxt, 'csp');
        for ( const directive of staticDirectives ) {
            if ( directive.result !== 1 ) { continue; }
            cspData.set(directive.data, directive.logData());
        }

        fctxt.type = 'inline-script';
        fctxt.filter = undefined;
        if ( pageStore.filterRequest(fctxt) === 1 ) {
            cspData.set(킶.cspNoInlineScript, fctxt.filter);
        }

        fctxt.type = 'script';
        fctxt.filter = undefined;
        if ( pageStore.filterScripting(fctxt, true) === 1 ) {
            cspData.set(킶.cspNoScripting, fctxt.filter);
        }
    
        fctxt.type = 'inline-font';
        fctxt.filter = undefined;
        if ( pageStore.filterRequest(fctxt) === 1 ) {
            cspData.set(킶.cspNoInlineFont, fctxt.filter);
        }

        if ( cspData.size === 0 ) { return false; }

        pageStore.extraData.set('cspData', cspData);
    }

    const typeMap = logCSPViolations.policyDirectiveToTypeMap;
    for ( const json of request.violations ) {
        const violation = JSON.parse(json);
        let type = typeMap.get(violation.directive);
        if ( type === undefined ) { continue; }
        const logData = cspData.get(violation.policy);
        if ( logData === undefined ) { continue; }
        if ( /^[\w.+-]+:\/\//.test(violation.url) === false ) {
            violation.url = request.docURL;
            if ( type === 'script' ) { type = 'inline-script'; }
            else if ( type === 'font' ) { type = 'inline-font'; }
        }
        fctxt.setURL(violation.url)
             .setType(type)
             .setFilter(logData)
             .toLogger();
    }

    return true;
};

logCSPViolations.policyDirectiveToTypeMap = new Map([
    [ 'img-src', 'image' ],
    [ 'connect-src', 'xmlhttprequest' ],
    [ 'font-src', 'font' ],
    [ 'frame-src', 'sub_frame' ],
    [ 'media-src', 'media' ],
    [ 'object-src', 'object' ],
    [ 'script-src', 'script' ],
    [ 'script-src-attr', 'script' ],
    [ 'script-src-elem', 'script' ],
    [ 'style-src', 'stylesheet' ],
    [ 'style-src-attr', 'stylesheet' ],
    [ 'style-src-elem', 'stylesheet' ],
]);

const onMessage = function(request, sender, callback) {
    const tabId = sender && sender.tab ? sender.tab.id : 0;
    const pageStore = 킶.pageStoreFromTabId(tabId);

    // Async
    switch ( request.what ) {
    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'applyFilterListSelection':
        response = 킶.applyFilterListSelection(request);
        break;

    case 'inlinescriptFound':
        if ( 킶.logger.enabled && pageStore !== null ) {
            const fctxt = 킶.filteringContext.duplicate();
            fctxt.fromTabId(tabId)
                .setType('inline-script')
                .setURL(request.docURL)
                .setDocOriginFromURL(request.docURL);
            if ( pageStore.filterRequest(fctxt) === 0 ) {
                fctxt.setRealm('network').toLogger();
            }
        }
        break;

    case 'logCosmeticFilteringData':
        logCosmeticFilters(tabId, request);
        break;

    case 'reloadAllFilters':
        킶.loadFilterLists();
        return;

    case 'securityPolicyViolation':
        response = logCSPViolations(pageStore, request);
        break;

    case 'temporarilyAllowLargeMediaElement':
        if ( pageStore !== null ) {
            pageStore.allowLargeMediaElementsUntil = Date.now() + 2000;
        }
        break;

    case 'subscriberData':
        response = {
            confirmStr: vAPI.i18n('subscriberConfirm')
        };
        break;

    default:
        return vAPI.messaging.UNHANDLED;
    }

    callback(response);
};

vAPI.messaging.listen({
    name: 'scriptlets',
    listener: onMessage,
});

// <<<<< end of local scope
}


/******************************************************************************/
/******************************************************************************/

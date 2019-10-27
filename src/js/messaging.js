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

const �b = �Block;

const getDomainNames = function(targets) {
    const �buri = �b.URI;
    return targets.map(target => {
        if ( typeof target !== 'string' ) { return ''; }
        return target.indexOf('/') !== -1
            ? �buri.domainFromURI(target) || ''
            : �buri.domainFromHostname(target) || target;
    });
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    case 'getAssetContent':
        // https://github.com/chrisaljoudi/uBlock/issues/417
        �b.assets.get(
            request.url,
            { dontCache: true, needSourceURL: true }
        ).then(result => {
            callback(result);
        });
        return;

    case 'listsFromNetFilter':
        �b.staticFilteringReverseLookup.fromNetFilter(
            request.rawFilter
        ).then(response => {
            callback(response);
        });
        return;

    case 'listsFromCosmeticFilter':
        �b.staticFilteringReverseLookup.fromCosmeticFilter(
            request
        ).then(response => {
            callback(response);
        });
        return;

    case 'reloadAllFilters':
        �b.loadFilterLists().then(( ) => { callback(); });
        return;

    case 'scriptlet':
        �b.scriptlets.inject(request.tabId, request.scriptlet, callback);
        return;

    default:
        break;
    }

    // Sync
    var response;

    switch ( request.what ) {
    case 'applyFilterListSelection':
        response = �b.applyFilterListSelection(request);
        break;

    case 'createUserFilter':
        �b.createUserFilters(request);
        break;

    case 'forceUpdateAssets':
        �b.scheduleAssetUpdater(0);
        �b.assets.updateStart({
            delay: �b.hiddenSettings.manualUpdateAssetFetchPeriod
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
            whitelist: �b.arrayFromWhitelist(�b.netWhitelist),
            whitelistDefault: �b.netWhitelistDefault,
            reBadHostname: �b.reWhitelistBadHostname.source,
            reHostnameExtractor: �b.reWhitelistHostnameExtractor.source
        };
        break;

    case 'launchElementPicker':
        // Launched from some auxiliary pages, clear context menu coords.
        �b.epickerArgs.mouse = false;
        �b.elementPickerExec(request.tabId, request.targetURL, request.zap);
        break;

    case 'gotoURL':
        �b.openNewTab(request.details);
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
        �b.netWhitelist = �b.whitelistFromString(request.whitelist);
        �b.saveWhitelist();
        break;

    case 'toggleHostnameSwitch':
        �b.toggleHostnameSwitch(request);
        break;

    case 'userSettings':
        response = �b.changeUserSettings(request.name, request.value);
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

const �b = �Block;

const getHostnameDict = function(hostnameToCountMap) {
    const r = Object.create(null);
    const domainFromHostname = �b.URI.domainFromHostname;
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
    var df = �b.sessionFirewall;
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
    const tabContext = �b.tabContextManager.mustLookup(tabId);
    const rootHostname = tabContext.rootHostname;
    const r = {
        advancedUserEnabled: �b.userSettings.advancedUserEnabled,
        appName: vAPI.app.name,
        appVersion: vAPI.app.version,
        colorBlindFriendly: �b.userSettings.colorBlindFriendly,
        cosmeticFilteringSwitch: false,
        dfEnabled: �b.userSettings.dynamicFilteringEnabled,
        firewallPaneMinimized: �b.userSettings.firewallPaneMinimized,
        globalAllowedRequestCount: �b.localSettings.allowedRequestCount,
        globalBlockedRequestCount: �b.localSettings.blockedRequestCount,
        fontSize: �b.hiddenSettings.popupFontSize,
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
        tooltipsDisabled: �b.userSettings.tooltipsDisabled
    };

    const pageStore = �b.pageStoreFromTabId(tabId);
    if ( pageStore ) {
        // https://github.com/gorhill/uBlock/issues/2105
        //   Be sure to always include the current page's hostname -- it
        //   might not be present when the page itself is pulled from the
        //   browser's short-term memory cache. This needs to be done
        //   before calling getHostnameDict().
        if (
            pageStore.hostnameToCountMap.has(rootHostname) === false &&
            �b.URI.isNetworkURI(tabContext.rawURL)
        ) {
            pageStore.hostnameToCountMap.set(rootHostname, 0);
        }
        r.pageBlockedRequestCount = pageStore.perLoadBlockedRequestCount;
        r.pageAllowedRequestCount = pageStore.perLoadAllowedRequestCount;
        r.netFilteringSwitch = pageStore.getNetFilteringSwitch();
        r.hostnameDict = getHostnameDict(pageStore.hostnameToCountMap);
        r.contentLastModified = pageStore.contentLastModified;
        r.firewallRules = getFirewallRules(rootHostname, r.hostnameDict);
        r.canElementPicker = �b.URI.isNetworkURI(r.rawURL);
        r.noPopups = �b.sessionSwitches.evaluateZ(
            'no-popups',
            rootHostname
        );
        r.popupBlockedCount = pageStore.popupBlockedCount;
        r.noCosmeticFiltering = �b.sessionSwitches.evaluateZ(
            'no-cosmetic-filtering',
            rootHostname
        );
        r.noLargeMedia = �b.sessionSwitches.evaluateZ(
            'no-large-media',
            rootHostname
        );
        r.largeMediaCount = pageStore.largeMediaCount;
        r.noRemoteFonts = �b.sessionSwitches.evaluateZ(
            'no-remote-fonts',
            rootHostname
        );
        r.remoteFontCount = pageStore.remoteFontCount;
        r.noScripting = �b.sessionSwitches.evaluateZ(
            'no-scripting',
            rootHostname
        );
    } else {
        r.hostnameDict = {};
        r.firewallRules = getFirewallRules();
    }

    r.matrixIsDirty = �b.sessionFirewall.hasSameRules(
        �b.permanentFirewall,
        rootHostname,
        r.hostnameDict
    ) === false;
    if ( r.matrixIsDirty === false ) {
        r.matrixIsDirty = �b.sessionSwitches.hasSameRules(
            �b.permanentSwitches,
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
        pageStore = �b.pageStoreFromTabId(request.tabId);
        var lastModified = pageStore ? pageStore.contentLastModified : 0;
        response = lastModified !== request.contentLastModified;
        break;

    case 'revertFirewallRules':
        �b.sessionFirewall.copyRules(
            �b.permanentFirewall,
            request.srcHostname,
            request.desHostnames
        );
        �b.sessionSwitches.copyRules(
            �b.permanentSwitches,
            request.srcHostname
        );
        // https://github.com/gorhill/uBlock/issues/188
        �b.cosmeticFilteringEngine.removeFromSelectorCache(
            request.srcHostname,
            'net'
        );
        �b.updateToolbarIcon(request.tabId, 0b100);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'saveFirewallRules':
        if (
            �b.permanentFirewall.copyRules(
                �b.sessionFirewall,
                request.srcHostname,
                request.desHostnames
            )
        ) {
            �b.savePermanentFirewallRules();
        }
        if (
            �b.permanentSwitches.copyRules(
                �b.sessionSwitches,
                request.srcHostname
            )
        ) {
            �b.saveHostnameSwitches();
        }
        break;

    case 'toggleHostnameSwitch':
        �b.toggleHostnameSwitch(request);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'toggleFirewallRule':
        �b.toggleFirewallRule(request);
        response = popupDataFromTabId(request.tabId);
        break;

    case 'toggleNetFiltering':
        pageStore = �b.pageStoreFromTabId(request.tabId);
        if ( pageStore ) {
            pageStore.toggleNetFilteringSwitch(
                request.url,
                request.scope,
                request.state
            );
            �b.updateToolbarIcon(request.tabId, 0b111);
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

const �b = �Block;

const retrieveContentScriptParameters = function(senderDetails, request) {
    const { url, tabId, frameId } = senderDetails;
    if ( url === undefined || tabId === undefined || frameId === undefined ) {
        return;
    }
    if ( request.url !== url ) { return; }
    const pageStore = �b.pageStoreFromTabId(tabId);
    if ( pageStore === null || pageStore.getNetFilteringSwitch() === false ) {
        return;
    }

    const noCosmeticFiltering = pageStore.noCosmeticFiltering === true;

    const response = {
        collapseBlocked: �b.userSettings.collapseBlocked,
        noCosmeticFiltering,
        noGenericCosmeticFiltering: noCosmeticFiltering,
        noSpecificCosmeticFiltering: noCosmeticFiltering,
    };

    // https://github.com/uBlockOrigin/uAssets/issues/5704
    //   `generichide` must be evaluated in the frame context.
    if ( noCosmeticFiltering === false ) {
        const genericHide =
            �b.staticNetFilteringEngine.matchStringElementHide(
                'generic',
                request.url
            );
        response.noGenericCosmeticFiltering = genericHide === 2;
        if ( genericHide !== 0 && �b.logger.enabled ) {
            �Block.filteringContext
                .duplicate()
                .fromTabId(tabId)
                .setURL(request.url)
                .setRealm('network')
                .setType('generichide')
                .setFilter(�b.staticNetFilteringEngine.toLogData())
                .toLogger();
        }
    }

    request.tabId = tabId;
    request.frameId = frameId;
    request.hostname = �b.URI.hostnameFromURI(request.url);
    request.domain = �b.URI.domainFromHostname(request.hostname);
    request.entity = �b.URI.entityFromDomain(request.domain);

    // https://www.reddit.com/r/uBlockOrigin/comments/d6vxzj/
    //   Add support for `specifichide`.
    if ( noCosmeticFiltering === false ) {
        const specificHide =
            �b.staticNetFilteringEngine.matchStringElementHide(
                'specific',
                request.url
            );
        response.noSpecificCosmeticFiltering = specificHide === 2;
        if ( specificHide !== 0 && �b.logger.enabled ) {
            �Block.filteringContext
                .duplicate()
                .fromTabId(tabId)
                .setURL(request.url)
                .setRealm('network')
                .setType('specifichide')
                .setFilter(�b.staticNetFilteringEngine.toLogData())
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
        �b.cosmeticFilteringEngine.retrieveSpecificSelectors(request, response);

    if ( �b.canInjectScriptletsNow === false ) {
        response.scriptlets = �b.scriptletFilteringEngine.retrieve(request);
    }

    if ( �b.logger.enabled && response.noCosmeticFiltering !== true ) {
        �b.logCosmeticFilters(tabId, frameId);
    }

    return response;
};

const onMessage = function(request, sender, callback) {
    // Async
    switch ( request.what ) {
    default:
        break;
    }

    const senderDetails = �b.getMessageSenderDetails(sender);
    const pageStore = �b.pageStoreFromTabId(senderDetails.tabId);

    // Sync
    let response;

    switch ( request.what ) {
    case 'cosmeticFiltersInjected':
        �b.cosmeticFilteringEngine.addToSelectorCache(request);
        break;

    case 'getCollapsibleBlockedRequests':
        response = {
            id: request.id,
            hash: request.hash,
            netSelectorCacheCountMax:
                �b.cosmeticFilteringEngine.netSelectorCacheCountMax,
        };
        if (
            �b.userSettings.collapseBlocked &&
            pageStore && pageStore.getNetFilteringSwitch()
        ) {
            pageStore.getBlockedResources(request, response);
        }
        break;

    case 'maybeGoodPopup':
        �b.maybeGoodPopup.tabId = senderDetails.tabId;
        �b.maybeGoodPopup.url = request.url;
        break;

    case 'shouldRenderNoscriptTags':
        if ( pageStore === null ) { break; }
        const fctxt = �b.filteringContext.fromTabId(senderDetails.tabId);
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
            result: �b.cosmeticFilteringEngine.retrieveGenericSelectors(request),
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
    const �b = �Block;

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
                target: �b.epickerArgs.target,
                mouse: �b.epickerArgs.mouse,
                zap: �b.epickerArgs.zap,
                eprom: �b.epickerArgs.eprom,
            });

            �b.epickerArgs.target = '';
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
        response = �b.staticExtFilteringEngine.compileSelector(
            request.selector
        );
        break;

    // https://github.com/gorhill/uBlock/issues/3497
    //   This needs to be removed once issue is fixed.
    case 'createUserFilter':
        �b.createUserFilters(request);
        break;

    case 'elementPickerEprom':
        �b.epickerArgs.eprom = request;
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
    if ( �Block.cloudStorageSupported !== true ) {
        callback();
        return;
    }

    // Async
    switch ( request.what ) {
    case 'cloudGetOptions':
        vAPI.cloud.getOptions(function(options) {
            options.enabled = �Block.userSettings.cloudStorageEnabled === true;
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

const �b = �Block;

// Settings
const getLocalData = async function() {
    const data = Object.assign({}, �b.restoreBackupSettings);
    data.storageUsed = await �b.getBytesInUse();
    data.cloudStorageSupported = �b.cloudStorageSupported;
    data.privacySettingsSupported = �b.privacySettingsSupported;
    return data;
};

const backupUserData = async function() {
    const userFilters = await �b.loadUserFilters();

    const userData = {
        timeStamp: Date.now(),
        version: vAPI.app.version,
        userSettings: �b.userSettings,
        selectedFilterLists: �b.selectedFilterLists,
        hiddenSettings: �b.hiddenSettings,
        whitelist: �b.arrayFromWhitelist(�b.netWhitelist),
        // String representation eventually to be deprecated
        netWhitelist: �b.stringFromWhitelist(�b.netWhitelist),
        dynamicFilteringString: �b.permanentFirewall.toString(),
        urlFilteringString: �b.permanentURLFiltering.toString(),
        hostnameSwitchesString: �b.permanentSwitches.toString(),
        userFilters: userFilters.content,
    };

    const filename = vAPI.i18n('aboutBackupFilename')
        .replace('{{datetime}}', �b.dateNowToSensibleString())
        .replace(/ +/g, '_');
    �b.restoreBackupSettings.lastBackupFile = filename;
    �b.restoreBackupSettings.lastBackupTime = Date.now();
    vAPI.storage.set(�b.restoreBackupSettings);

    const localData = await getLocalData();

    return { localData, userData };
};

const restoreUserData = async function(request) {
    const userData = request.userData;

    // https://github.com/chrisaljoudi/uBlock/issues/1102
    //   Ensure all currently cached assets are flushed from storage AND memory.
    �b.assets.rmrf();

    // If we are going to restore all, might as well wipe out clean local
    // storages
    vAPI.localStorage.removeItem('immediateHiddenSettings');
    await Promise.all([
        �b.cacheStorage.clear(),
        vAPI.storage.clear(),
    ]);

    // Restore block stats
    �Block.saveLocalSettings();

    // Restore user data
    vAPI.storage.set(userData.userSettings);
    let hiddenSettings = userData.hiddenSettings;
    if ( hiddenSettings instanceof Object === false ) {
        hiddenSettings = �Block.hiddenSettingsFromString(
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
    �b.saveUserFilters(userData.userFilters);
    if ( Array.isArray(userData.selectedFilterLists) ) {
         await �b.saveSelectedFilterLists(userData.selectedFilterLists);
    }

    vAPI.app.restart();
};

// Remove all stored data but keep global counts, people can become
// quite attached to numbers
const resetUserData = async function() {
    vAPI.localStorage.removeItem('immediateHiddenSettings');

    await Promise.all([
        �b.cacheStorage.clear(),
        vAPI.storage.clear(),
    ]);

    await �b.saveLocalSettings();

    vAPI.app.restart();
};

// 3rd-party filters
const prepListEntries = function(entries) {
    const �buri = �b.URI;
    for ( const k in entries ) {
        if ( entries.hasOwnProperty(k) === false ) { continue; }
        const entry = entries[k];
        if ( typeof entry.supportURL === 'string' && entry.supportURL !== '' ) {
            entry.supportName = �buri.hostnameFromURI(entry.supportURL);
        } else if ( typeof entry.homeURL === 'string' && entry.homeURL !== '' ) {
            const hn = �buri.hostnameFromURI(entry.homeURL);
            entry.supportURL = `http://${hn}/`;
            entry.supportName = �buri.domainFromHostname(hn);
        }
    }
};

const getLists = async function(callback) {
    const r = {
        autoUpdate: �b.userSettings.autoUpdate,
        available: null,
        cache: null,
        cosmeticFilterCount: �b.cosmeticFilteringEngine.getFilterCount(),
        current: �b.availableFilterLists,
        externalLists: �b.userSettings.externalLists,
        ignoreGenericCosmeticFilters: �b.userSettings.ignoreGenericCosmeticFilters,
        isUpdating: �b.assets.isUpdating(),
        netFilterCount: �b.staticNetFilteringEngine.getFilterCount(),
        parseCosmeticFilters: �b.userSettings.parseAllABPHideFilters,
        userFiltersPath: �b.userFiltersPath
    };
    const [ lists, metadata ] = await Promise.all([
        �b.getAvailableLists(),
        �b.assets.metadata(),
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
            �b.permanentFirewall.toArray().concat(
                �b.permanentSwitches.toArray(),
                �b.permanentURLFiltering.toArray()
            ),
        sessionRules:
            �b.sessionFirewall.toArray().concat(
                �b.sessionSwitches.toArray(),
                �b.sessionURLFiltering.toArray()
            )
    };
};

const modifyRuleset = function(details) {
    let swRuleset, hnRuleset, urlRuleset;
    if ( details.permanent ) {
        swRuleset = �b.permanentSwitches;
        hnRuleset = �b.permanentFirewall;
        urlRuleset = �b.permanentURLFiltering;
    } else {
        swRuleset = �b.sessionSwitches;
        hnRuleset = �b.sessionFirewall;
        urlRuleset = �b.sessionURLFiltering;
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
            �b.saveHostnameSwitches();
            swRuleset.changed = false;
        }
        if ( hnRuleset.changed ) {
            �b.savePermanentFirewallRules();
            hnRuleset.changed = false;
        }
        if ( urlRuleset.changed ) {
            �b.savePermanentURLFilteringRules();
            urlRuleset.changed = false;
        }
    }
};

// Shortcuts pane
const getShortcuts = function(callback) {
    if ( �b.canUseShortcuts === false ) {
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
    if  ( �b.canUpdateShortcuts === false ) { return; }
    if ( details.shortcut === undefined ) {
        vAPI.commands.reset(details.name);
        �b.commandShortcuts.delete(details.name);
    } else {
        vAPI.commands.update({ name: details.name, shortcut: details.shortcut });
        �b.commandShortcuts.set(details.name, details.shortcut);
    }
    vAPI.storage.set({ commandShortcuts: Array.from(�b.commandShortcuts) });
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
        return �b.loadUserFilters().then(result => {
            callback(result);
        });

    case 'writeUserFilters':
        return �b.saveUserFilters(request.content).then(result => {
            callback(result);
        });

    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'canUpdateShortcuts':
        response = �b.canUpdateShortcuts;
        break;

    case 'getRules':
        response = getRules();
        break;

    case 'modifyRuleset':
        // https://github.com/chrisaljoudi/uBlock/issues/772
        �b.cosmeticFilteringEngine.removeFromSelectorCache('*');
        modifyRuleset(request);
        response = getRules();
        break;

    case 'purgeAllCaches':
        if ( request.hard ) {
            �b.assets.remove(/./);
        } else {
            �b.assets.purge(/./, 'public_suffix_list.dat');
        }
        break;

    case 'purgeCache':
        �b.assets.purge(request.assetKey);
        �b.assets.remove('compiled/' + request.assetKey);
        break;

    case 'readHiddenSettings':
        response = �b.stringFromHiddenSettings();
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
        �b.changeHiddenSettings(�b.hiddenSettingsFromString(request.content));
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

const �b = �Block;
const extensionOriginURL = vAPI.getURL('');

const getLoggerData = async function(details, activeTabId, callback) {
    const response = {
        activeTabId,
        colorBlind: �b.userSettings.colorBlindFriendly,
        entries: �b.logger.readAll(details.ownerId),
        filterAuthorMode: �b.hiddenSettings.filterAuthorMode,
        maxEntries: �b.userSettings.requestLogMaxEntries,
        tabIdsToken: �b.pageStoresToken,
        tooltips: �b.userSettings.tooltipsDisabled === false
    };
    if ( �b.pageStoresToken !== details.tabIdsToken ) {
        const tabIds = new Map();
        for ( const entry of �b.pageStores ) {
            const pageStore = entry[1];
            if ( pageStore.rawURL.startsWith(extensionOriginURL) ) { continue; }
            tabIds.set(entry[0], pageStore.title);
        }
        response.tabIds = Array.from(tabIds);
    }
    if ( activeTabId ) {
        const pageStore = �b.pageStoreFromTabId(activeTabId);
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
    const suf = �b.sessionURLFiltering;
    const puf = �b.permanentURLFiltering;
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
        session = �b.scriptletFilteringEngine.getSession();
    } else {
        if ( selector.startsWith('^') ) {
            session = �b.htmlFilteringEngine.getSession();
        } else {
            session = �b.cosmeticFilteringEngine.getSession();
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
            �b.logger.ownerId !== undefined &&
            �b.logger.ownerId !== request.ownerId
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
        if ( request.ownerId === �b.logger.ownerId ) {
            �b.logger.ownerId = undefined;
        }
        break;

    case 'saveURLFilteringRules':
        response = �b.permanentURLFiltering.copyRules(
            �b.sessionURLFiltering,
            request.context,
            request.urls,
            request.type
        );
        if ( response ) {
            �b.savePermanentURLFilteringRules();
        }
        break;

    case 'setURLFilteringRule':
        �b.toggleURLFilteringRule(request);
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
        �Block.webRequest.strictBlockBypass(request.hostname);
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

const �b = �Block;

const logCosmeticFilters = function(tabId, details) {
    if ( �b.logger.enabled === false ) { return; }

    const filter = { source: 'cosmetic', raw: '' };
    const fctxt = �b.filteringContext.duplicate();
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
    if ( �b.logger.enabled === false || pageStore === null ) {
        return false;
    }
    if ( request.violations.length === 0 ) {
        return true;
    }

    const fctxt = �b.filteringContext.duplicate();
    fctxt.fromTabId(pageStore.tabId)
         .setRealm('network')
         .setDocOriginFromURL(request.docURL)
         .setURL(request.docURL);

    let cspData = pageStore.extraData.get('cspData');
    if ( cspData === undefined ) {
        cspData = new Map();

        const staticDirectives =
            �b.staticNetFilteringEngine.matchAndFetchData(fctxt, 'csp');
        for ( const directive of staticDirectives ) {
            if ( directive.result !== 1 ) { continue; }
            cspData.set(directive.data, directive.logData());
        }

        fctxt.type = 'inline-script';
        fctxt.filter = undefined;
        if ( pageStore.filterRequest(fctxt) === 1 ) {
            cspData.set(�b.cspNoInlineScript, fctxt.filter);
        }

        fctxt.type = 'script';
        fctxt.filter = undefined;
        if ( pageStore.filterScripting(fctxt, true) === 1 ) {
            cspData.set(�b.cspNoScripting, fctxt.filter);
        }
    
        fctxt.type = 'inline-font';
        fctxt.filter = undefined;
        if ( pageStore.filterRequest(fctxt) === 1 ) {
            cspData.set(�b.cspNoInlineFont, fctxt.filter);
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
    const pageStore = �b.pageStoreFromTabId(tabId);

    // Async
    switch ( request.what ) {
    default:
        break;
    }

    // Sync
    let response;

    switch ( request.what ) {
    case 'applyFilterListSelection':
        response = �b.applyFilterListSelection(request);
        break;

    case 'inlinescriptFound':
        if ( �b.logger.enabled && pageStore !== null ) {
            const fctxt = �b.filteringContext.duplicate();
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
        �b.loadFilterLists();
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

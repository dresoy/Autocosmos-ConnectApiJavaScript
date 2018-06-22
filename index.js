$(function () {
    var $domain = $('input[name="domain"]');
    var $appkey = $('input[name="appkey"]');
    var $appsecret = $('input[name="appsecret"]');
    var $accountSignature = $('input[name="accountSignature"]');
    var $endpoint = $('input[name="endpoint"]');
    var $httpMethod = $('select[name="httpMethod"]');
    var $rqContent = $('textarea[name="rqContent"]');
    var $responseContainer = $('[data-role="response-container"]');
    var $responseStatus = $('#response-status');
    var $responseContent = $('#response');
    var $requestProgress = $('[data-role="request-progress"]');

    $('#testContent').submit(function (evt) {
        evt.preventDefault();
        sendRequest();
        return false;
    });
    $endpoint.on('input propertychange paste', function () {
        $('#endpointHelp').text('URI: ' + $domain.val() + $endpoint.val());
    });
    $('#endpointHelp').text('URI: ' + $domain.val() + $endpoint.val());

    function canonicalSignatureString(method, cmd5, ctype, headers, pathQuery) {
        function getCanonicalParts() {
            /*
            Ver : https://www.autocosmos.com.ar/developers/help/hmac
            1.Request method (GET,POST,PUT,DELETE,PATCH, etc.)
            2.Header Content-Md5
            3.Header Content-Type
            4.Header Date
            5.Todos los headers que empiezan con X-ACS- canonizados.
            6.URI (path + query) del request
            */
            var parts = [];
            parts.push(method);
            cmd5 && cmd5.length > 0 ? parts.push(cmd5) : parts.push('');
            ctype && ctype.length > 0 ? parts.push(ctype) : parts.push('');
            parts.push(''); // Ya que usamos el ACS-header para especificar el timeStamp agregamos el Date en blanco
            if (headers) {
                // Headers de ACS ordenados, lowercase, trimmed
                Array.from(headers)
                    .sort(function (a, b) {
                        return a[0].toLowerCase().trim() > b[0].toLowerCase().trim();
                    })
                    .forEach(function (e, idx) {
                        parts.push(e[0].toLowerCase().trim() + ':' + e[1]);
                    });
            }
            parts.push(pathQuery);
            return parts;
        };
        // Todos los componentes de la signature son separadas por new-line (\n)
        return getCanonicalParts().join('\n');
    };

    function getAuthSignature(canonicalized) {
        var appsecret = $appsecret.val();
        var secretBytes = sjcl.codec.utf8String.toBits(appsecret);
        var canonicalizedBytes = sjcl.codec.utf8String.toBits(canonicalized);
        var hmac = new sjcl.misc.hmac(secretBytes, sjcl.hash.sha256);
        var signatureBytes = hmac.mac(canonicalizedBytes);
        return sjcl.codec.base64.fromBits(signatureBytes);
    };

    function sendRequest() {
        var domain = $domain.val();
        var appkey = $appkey.val();
        var accountSignature = $accountSignature.val();
        var endpoint = $endpoint.val();
        var httpMethod = $httpMethod.val();
        var acsHeaders = new Map([
            ['X-ACS-Date', (new Date()).toUTCString()]
        ]);
        var requestContent = $rqContent.val();
        accountSignature && accountSignature.length > 0 && acsHeaders.set('X-ACS-User-Signature',
            accountSignature);
        var payload = (httpMethod === 'POST' || httpMethod === 'PUT' || httpMethod === 'PATCH') ?
            requestContent : null;
        var contentMd5 = payload ? md5.base64(payload) : null;
        var contentType = payload ? 'application/json' : null;
        var canonicalized = canonicalSignatureString(httpMethod, contentMd5, contentType,
            acsHeaders, endpoint);
        var signature = getAuthSignature(canonicalized);

        // Construye todos los headers del request
        var headers = {};
        headers['Authorization'] = 'ACS-H ' + appkey + ':' + signature;
        headers['Accept'] = 'application/json';
        contentType && (headers['Content-Type'] = contentType);
        contentMd5 && (headers['Content-MD5'] = contentMd5);
        acsHeaders.forEach(function (v, k) {
            headers[k] = v;
        });

        $requestProgress.show(1000);
        $responseStatus.text('');
        $responseContent.text('');
        $.ajax({
                url: domain + endpoint,
                type: httpMethod,
                headers: headers,
                data: payload
            })
            .done(function (responseData, statusText, xhr) {
                $responseContainer.removeClass('border-danger').addClass('border-primary');
                $requestProgress.hide();
                $responseStatus.text(xhr.status);
                var s = JSON.stringify(responseData, null, 4);
                $responseContent.text(s);
            }).fail(function (xhr, ts, exception) {
                $responseContainer.removeClass('border-primary').addClass('border-danger');
                $requestProgress.hide();
                $responseStatus.text(xhr.status);
                $responseContent.text((xhr.responseText || ts));
            });
        console.log('canonicalized="' + canonicalized + '"');
        console.log('Auth Signature="' + signature + '"');
    };
    //==========================================================

});
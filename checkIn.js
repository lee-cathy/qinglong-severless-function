/*
领京豆签到
cron:15 0,16 * * *
cron "0 7 * * *" checkIn.js, tag=haval-checkin
*/
const JSEncrypt = require('node-jsencrypt');
const axios = require('axios');
const CryptoJS = require('crypto-js');
const MD5 = require('md5');
const {serverNotify} = require("./serverNotify.js");

function stringReverse(num) {
    return num.split('').reverse().join('');
}
function randomString(m) {
    for (var e = m > 0 && void 0 !== m ? m : 21, t = ""; t.length < e;) t += Math.random().toString(36).slice(2);
    return t.slice(0, e)
}
function randomszxx(e) {
    e = e || 32;
    var t = "qwertyuioplkjhgfdsazxcvbnm1234567890",
        a = t.length,
        n = "";

    for (let i = 0; i < e; i++) n += t.charAt(Math.floor(Math.random() * a));
    return n;
}

function AES_Encrypt(word) {
    const key = CryptoJS.enc.Utf8.parse("60532EB847CFB989");
    const iv = CryptoJS.enc.Utf8.parse("0FF5A43FDAFCEF98");
    const srcs = CryptoJS.enc.Utf8.parse(word);
    const encrypted = CryptoJS.AES.encrypt(srcs, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}
async function accountLogin(phone, password, timestamp) {
    const jsEncrypt = new JSEncrypt();
    let key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD1rUMmlDWqdpYqYcYtplkatoK+H7mEu0d0/ml3IGYT+K4Lm0IfoPLOVi5fLBLmfi08yCnVQQWdJSjV1nDTV52eNFL2H5Rus8lBQkInuratA1iVOXh/7TL4uW8UPJG8flpkJ2dQlRVLSGy+UK3+R14vxy/yhrVcmvygGL5qRf8ZBwIDAQAB"
    jsEncrypt.setPublicKey(key);
    let secret = jsEncrypt.encrypt('60532EB847CFB989A59C5AF2ABC51713haval');
    let isecret = jsEncrypt.encrypt('0FF5A43FDAFCEF98')
    let t = timestamp
    let body = `{"account":"${phone}","aliyunDeviceToken":"","appType":"0","cVer":"4.4.900","password":"${password}","pushId":"","pushKey":"","timestamp":"${t}"}`
    body = AES_Encrypt(body)
    let options = {
        method: 'POST',
        url: 'https://amp.gwm.com.cn/web/haval/v1/sso/account-login',
        params: { cVer: '4.4.900' },
        headers: {
            secret: encodeURIComponent(secret),
            isecret: encodeURIComponent(isecret),
            'Content-Type': 'text/html; charset=UTF-8',
            Host: 'amp.gwm.com.cn',
            Connection: 'keep-alive',
            'User-Agent': 'okhttp/4.2.2',
            Accept: '*/*',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'X-Requested-With',
            Vary: 'Accept-Encoding',
            SSOAccessToken: 'SSOAccessToken',
            SSOuid: 'SSOuid',
            mallToken: '',
            tokenId: '',
            cVer: '4.4.900',
            ptToken: '',
            nowTime: stringReverse(t),
            forumSecret: MD5('AP463000936709619712' + t + 'f90845a088c74b8497b3cc1d3909abcc'),
            'Accept-Encoding': 'gzip, deflate',

        },
        data: body
    };
    const response = await axios.request(options)
    let data = response.data;
    return {
        tel: data.object.SSO.phone,
        ptToken: data.object.SSO.ptToken,
        ssoId: data.object.SSO.suserId,
        tokenId: data.object.TSP.tokenId,
        nickName: data.object.TSP.nickName
    }
}
function getSign(method, url, nonce, ts, data) {
    let r = encodeURIComponent(method + url + 'bt-auth-appkey:7736975579' + 'bt-auth-nonce:' + nonce + 'bt-auth-timestamp:' + ts + data + '8a23355d9f6a3a41deaf37a628645c62')
    return CryptoJS.SHA256(r).toString()
}
async function loginSSOAccount(SSOInfo, timestamp) {
    let urls = '/app-api/api/v1.0/userAuth/loginSSOAccount'
    let nonce = randomszxx(16)
    let t = timestamp
    let body = `{"appType":"0","areaCode":"","deviceId":"${randomString(32)}","phone":"${SSOInfo.tel}","pushType":"2","ssoId":"${SSOInfo.ssoId}","ssoToken":"${SSOInfo.ptToken}","tokenId":"${SSOInfo.tokenId}","xingeAppid":"1500002164","xingeToken":"048315e62504714231558ec89c242a386905"}`
    let signs = getSign('POST', urls, nonce, t, 'json=' + body)

    var options = {
        method: 'POST',
        url: 'https://gw-app.beantechyun.com/app-api/api/v1.0/userAuth/loginSSOAccount',
        headers: {
            'bt-auth-nonce': nonce,
            ip: '192.168.1.4',
            'bt-auth-timestamp': t,
            'bt-auth-sign': signs,
            rs: '2',
            'bt-auth-appkey': '7736975579',
            terminal: 'GW_APP_Haval',
            enterpriseId: 'CC01',
            sys: 'Android',
            brand: '1',
            cVer: '4.4.900',
            'Content-Type': 'application/json; charset=UTF-8',
            Host: 'gw-app.beantechyun.com',
            Connection: 'Keep-Alive',
            'User-Agent': 'okhttp/4.2.2',
            'Accept-Encoding': 'gzip, deflate',

        },
        data: body
    };
    const response = await axios.request(options)
    let data = response.data;
    if (data.code == "000000") {
        const accessToken = data.data.accessToken
        return accessToken;
    } else {
        return "";
    }
}

async function getUserInfo(phone, password) {
    const timestamp = Math.round(new Date().getTime()).toString()
    try {
        const ssoInfo = await accountLogin(phone, password, timestamp);
        const accessToken = await loginSSOAccount(ssoInfo, timestamp)

        return {
            name: ssoInfo.nickName,
            accessToken
        }
    } catch (error) {
        console.log(error)
        return {};
    }
}

function getRequestOptions(accessToken) {
    const myHeaders = new Headers()
    myHeaders.append('bt-auth-appKey', '7849495624')
    myHeaders.append('brand', '1')
    myHeaders.append('cVer', '5.0.400')
    myHeaders.append('accessToken', accessToken)
    myHeaders.append('rs', '2')
    myHeaders.append('terminal', 'GW_APP_Haval')
    myHeaders.append('tokenId', '5d495c16fa244feb8bbc896828e899b2')
    myHeaders.append('enterpriseId', 'CC01')
    const requestOptions = {
        headers: myHeaders,
        redirect: 'follow',
    }
    return requestOptions;
}


async function doRequest(url, method, requestOptions, needJson = true) {
    const response = await fetch(url, {
        ...requestOptions,
        method,
    })
    if (needJson)
        return response.json()

    else
        return response
}

async function checkIn(requestOptions) {
    const checkInUrl = 'https://bt-h5-gateway.beantechyun.com/app-api/api/v1.0/signIn/sign'
    try {

        const checkInData = await doRequest(checkInUrl, 'POST', requestOptions)
        if (checkInData.code === '651028') {
            console.log('Today is checked')
        }
        else if (checkInData.code === '610502') {
            console.log('Token has been expired.')
        }
        else if (checkInData.code === '000000') {
            console.log('Check in success.')
        }
        else {
            console.log('Unknown status', checkInData)
        }
    }
    catch (error) {
        console.log('Check in failed.')
    }
}

async function getSignInStatus(requestOptions) {
    const checkInUrl = 'https://bt-h5-gateway.beantechyun.com/app-api/api/v1.0/signIn/getUserSignInStatus'
    try {
        const signInStatus = await doRequest(checkInUrl, 'GET', requestOptions)
        if (signInStatus.code === '000000') {
            const userData = signInStatus.data
            const content = `You have check in for ${userData.continueSignDays} consecutive days, Today you gained ${userData.signPoint} points, and totally, you got: ${userData.remindPoint} points.`;
            serverNotify("Haval CheckIn Bot", content)
            console.log(content)
        }
        else {
            console.log('Unknown status', signInStatus)
        }
    }
    catch (error) {
        console.log('Get signin status failed', error)
    }
}


async function start() {
    const userInfo = await getUserInfo(process.env.HavalAccount, process.env.HavalPassword)
    if (!userInfo.accessToken || userInfo.accessToken === "") {
        console.log('Get user info failed');
    } else {
        console.log(`Hi, ${userInfo.name}`)
        const requestOptions = getRequestOptions(userInfo.accessToken);
        await checkIn(requestOptions)
        await getSignInStatus(requestOptions)
    }
}

(async () => {
    await start();
})()

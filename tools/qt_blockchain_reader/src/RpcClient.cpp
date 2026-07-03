#include "RpcClient.h"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTextStream>
#include <QUrl>

#include <cstdlib>

namespace {
QString toCompactText(const QJsonValue &v) {
    if (v.isObject()) return QString::fromUtf8(QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact));
    if (v.isArray()) return QString::fromUtf8(QJsonDocument(v.toArray()).toJson(QJsonDocument::Compact));
    if (v.isString()) return v.toString();
    if (v.isBool()) return v.toBool() ? "true" : "false";
    if (v.isDouble()) return QString::number(v.toDouble(), 'g', 16);
    if (v.isNull()) return "null";
    return "<undefined>";
}

QString bodyPreview(const QByteArray &body) {
    constexpr int kMaxPreview = 512;
    QString text = QString::fromUtf8(body);
    if (text.size() > kMaxPreview) {
        text = text.left(kMaxPreview) + "...";
    }
    return text;
}

QString extractRpcErrorFromBody(const QByteArray &body) {
    QJsonParseError parseError;
    const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error != QJsonParseError::NoError || !doc.isObject()) return QString();

    const QJsonObject root = doc.object();
    const QJsonValue err = root.value("error");
    if (err.isNull() || err.isUndefined()) return QString();

    if (err.isObject()) {
        const QJsonObject e = err.toObject();
        const QString codeText = e.contains("code") ? toCompactText(e.value("code")) : "?";
        const QString msgText = e.contains("message") ? toCompactText(e.value("message")) : toCompactText(err);
        return QString("RPC error %1: %2").arg(codeText, msgText);
    }

    return QString("RPC error: %1").arg(toCompactText(err));
}

QString homeDir() {
    const char *h = std::getenv("HOME");
    return h ? QString::fromUtf8(h) : QString();
}

bool loadRpcAuthFromConf(QString *userOut, QString *passOut) {
    const QString home = homeDir();
    if (home.isEmpty()) return false;

    QFile f(home + "/.gapcoin/gapcoin.conf");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return false;

    QString user;
    QString pass;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString raw = in.readLine().trimmed();
        if (raw.isEmpty() || raw.startsWith('#')) continue;
        const int eq = raw.indexOf('=');
        if (eq <= 0) continue;
        const QString key = raw.left(eq).trimmed();
        const QString val = raw.mid(eq + 1).trimmed();
        if (key == "rpcuser") user = val;
        else if (key == "rpcpassword") pass = val;
    }

    if (user.isEmpty() || pass.isEmpty()) return false;
    *userOut = user;
    *passOut = pass;
    return true;
}

bool loadRpcAuthFromCookie(QString *userOut, QString *passOut) {
    const QString home = homeDir();
    if (home.isEmpty()) return false;

    QFile f(home + "/.gapcoin/.cookie");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return false;

    const QString cookie = QString::fromUtf8(f.readAll()).trimmed();
    if (cookie.isEmpty()) return false;

    const int sep = cookie.indexOf(':');
    if (sep <= 0 || sep >= cookie.size() - 1) return false;

    *userOut = cookie.left(sep);
    *passOut = cookie.mid(sep + 1);
    return true;
}
} // namespace

RpcClient::RpcClient(QObject *parent) : QObject(parent) {}

void RpcClient::setEndpoint(const QString &url, const QString &user, const QString &pass) {
    url_ = url;
    user_ = user;
    pass_ = pass;
}

void RpcClient::call(const QString &method, const QJsonArray &params, SuccessCb onSuccess, ErrorCb onError) {
    if (url_.isEmpty()) {
        onError("RPC URL is empty.");
        return;
    }

    QNetworkRequest request{QUrl(url_)};
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QString authUser = user_;
    QString authPass = pass_;
    if (authUser.isEmpty() && authPass.isEmpty()) {
        if (!loadRpcAuthFromConf(&authUser, &authPass)) {
            loadRpcAuthFromCookie(&authUser, &authPass);
        }
    }

    const bool haveAuth = !authUser.isEmpty() || !authPass.isEmpty();
    if (haveAuth) {
        const QByteArray auth = (authUser + ":" + authPass).toUtf8().toBase64();
        request.setRawHeader("Authorization", QByteArray("Basic ") + auth);
    }

    QJsonObject payload;
    payload.insert("jsonrpc", "1.0");
    payload.insert("id", "qt-reader");
    payload.insert("method", method);
    payload.insert("params", params);

    QNetworkReply *reply = network_.post(request, QJsonDocument(payload).toJson(QJsonDocument::Compact));
    connect(reply, &QNetworkReply::finished, this, [reply, onSuccess, onError, haveAuth]() {
        const QByteArray body = reply->readAll();
        const QVariant httpStatusVar = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        const int httpStatus = httpStatusVar.isValid() ? httpStatusVar.toInt() : 0;

        if (reply->error() != QNetworkReply::NoError) {
            const QString rpcErr = extractRpcErrorFromBody(body);
            if (!rpcErr.isEmpty()) {
                onError(rpcErr);
                reply->deleteLater();
                return;
            }
            const QString statusSuffix = (httpStatus > 0) ? QString(" (HTTP %1)").arg(httpStatus) : QString();
            onError(QString("Network error: %1%2").arg(reply->errorString(), statusSuffix));
            reply->deleteLater();
            return;
        }

        if (httpStatus > 0 && (httpStatus < 200 || httpStatus >= 300)) {
            if (httpStatus == 401) {
                const QString hint = haveAuth
                    ? "RPC authentication failed (401). Check rpcuser/rpcpassword or cookie."
                    : "RPC authentication required (401). Enter rpcuser/rpcpassword or ensure ~/.gapcoin/gapcoin.conf or ~/.gapcoin/.cookie is readable.";
                onError(hint);
                reply->deleteLater();
                return;
            }
            onError(QString("HTTP error %1: %2").arg(httpStatus).arg(bodyPreview(body)));
            reply->deleteLater();
            return;
        }

        QJsonParseError parseError;
        const QJsonDocument doc = QJsonDocument::fromJson(body, &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            onError(QString("Invalid JSON response: %1. Body: %2")
                        .arg(parseError.errorString(), bodyPreview(body)));
            reply->deleteLater();
            return;
        }

        const QJsonObject root = doc.object();
        if (!root.contains("result") && !root.contains("error")) {
            onError(QString("Malformed RPC response: missing both 'result' and 'error'. Body: %1")
                        .arg(bodyPreview(body)));
            reply->deleteLater();
            return;
        }

        const QJsonValue err = root.value("error");
        if (!err.isNull() && !err.isUndefined()) {
            if (err.isObject()) {
                const QJsonObject e = err.toObject();
                const QString codeText = e.contains("code") ? toCompactText(e.value("code")) : "?";
                const QString msgText = e.contains("message") ? toCompactText(e.value("message")) : toCompactText(err);
                onError(QString("RPC error %1: %2")
                            .arg(codeText)
                            .arg(msgText));
            } else {
                onError(QString("RPC error: %1").arg(toCompactText(err)));
            }
            reply->deleteLater();
            return;
        }

        onSuccess(root.value("result"));
        reply->deleteLater();
    });
}

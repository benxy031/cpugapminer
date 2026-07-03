#pragma once

#include <QJsonArray>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QObject>
#include <functional>

class RpcClient : public QObject {
public:
    using SuccessCb = std::function<void(const QJsonValue &result)>;
    using ErrorCb = std::function<void(const QString &message)>;

    explicit RpcClient(QObject *parent = nullptr);

    void setEndpoint(const QString &url, const QString &user, const QString &pass);
    void call(const QString &method, const QJsonArray &params, SuccessCb onSuccess, ErrorCb onError);

private:
    QNetworkAccessManager network_;
    QString url_;
    QString user_;
    QString pass_;
};

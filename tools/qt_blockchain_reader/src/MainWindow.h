#pragma once

#include "RpcClient.h"

#include <QHash>
#include <QJsonObject>
#include <QMainWindow>
#include <QNetworkAccessManager>

class QLineEdit;
class QLabel;
class QCheckBox;
class QComboBox;
class QSpinBox;
class QTableWidget;
class QPlainTextEdit;
class QPushButton;
class QTimer;
class QWidget;

class MainWindow : public QMainWindow {
public:
    explicit MainWindow(QWidget *parent = nullptr);

private:
    void setupUi();
    void setBusy(bool busy);
    void showError(const QString &message);
    void refreshOverview();
    void loadRecentBlocks();
    void fetchBlockByHeight(int height, int remaining);
    void showBlockDetails(const QJsonObject &block);
    void lookupBlock();
    void stepBlockHeight(int delta);
    void lookupTransaction();
    void refreshPeers();
    void refreshPeerWindow();
    void showSelectedPeerDetails(int row);
    void loadHistoricalChartSamples();
    void pollLiveTip();
    void fetchRecordsLive();
    void applyRecordBadge(int row, int gap, double merit);

    RpcClient rpc_;
    bool busy_ = false;
    int currentBlockHeight_ = -1;
    int lastKnownTip_ = -1;
    bool historicalSamplesLoaded_ = false;
    bool historicalSamplesLoading_ = false;
    bool hashCalibrationReady_ = false;
    double hashPerDifficulty_ = -1.0;
    QHash<int, double> recordMeritByGap_;

    QLineEdit *urlEdit_ = nullptr;
    QLineEdit *userEdit_ = nullptr;
    QLineEdit *passEdit_ = nullptr;
    QPushButton *connectBtn_ = nullptr;
    QPushButton *refreshBtn_ = nullptr;
    QCheckBox *liveModeToggle_ = nullptr;

    QLabel *chainValue_ = nullptr;
    QLabel *heightValue_ = nullptr;
    QLabel *headersValue_ = nullptr;
    QLabel *difficultyValue_ = nullptr;
    QLabel *networkSpeedValue_ = nullptr;
    QLabel *bestHashValue_ = nullptr;
    QLabel *progressValue_ = nullptr;
    QLabel *peersOverviewValue_ = nullptr;
    QWidget *diffHashChart_ = nullptr;
    QComboBox *chartModeCombo_ = nullptr;
    QCheckBox *chartSamplesToggle_ = nullptr;

    QSpinBox *recentCount_ = nullptr;
    QPushButton *loadBlocksBtn_ = nullptr;
    QTableWidget *blocksTable_ = nullptr;

    QLineEdit *blockLookupEdit_ = nullptr;
    QPushButton *blockLookupBtn_ = nullptr;
    QPushButton *blockPrevBtn_ = nullptr;
    QPushButton *blockNextBtn_ = nullptr;
    QLabel *peersBlockValue_ = nullptr;
    QPlainTextEdit *blockDetails_ = nullptr;

    QLineEdit *txidEdit_ = nullptr;
    QLineEdit *txBlockHashEdit_ = nullptr;
    QPushButton *txLookupBtn_ = nullptr;
    QLabel *peersTxValue_ = nullptr;
    QPlainTextEdit *txDetails_ = nullptr;

    QPushButton *peersRefreshBtn_ = nullptr;
    QTableWidget *peersTable_ = nullptr;
    QPlainTextEdit *peerDetails_ = nullptr;

    QLabel *recordsStatusValue_ = nullptr;
    QTimer *recordsTimer_ = nullptr;
    QTimer *liveTimer_ = nullptr;
    QNetworkAccessManager recordsNetwork_;
};

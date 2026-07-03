#include "MainWindow.h"

#include <QDateTime>
#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVector>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <memory>

namespace {
constexpr const char *kRecordsUrl = "https://primegaps.cloudygo.com/merits.txt";

QString prettyJson(const QJsonValue &value) {
    if (value.isObject()) return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Indented));
    if (value.isArray()) return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Indented));
    return value.toVariant().toString();
}

QString shortHash(const QString &hash) {
    if (hash.size() <= 20) return hash;
    return hash.left(10) + "..." + hash.right(10);
}

QString fixed4(double v) {
    return QString::number(v, 'f', 4);
}

QString formatHashrate(double hps) {
    if (hps < 0.0) return "n/a";
    static const char *kUnits[] = {"H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"};
    int unit = 0;
    while (hps >= 1000.0 && unit < 5) {
        hps /= 1000.0;
        ++unit;
    }
    return QString::number(hps, 'f', (hps >= 100.0 ? 1 : (hps >= 10.0 ? 2 : 3))) + " " + kUnits[unit];
}

class MiniDiffHashChart : public QWidget {
public:
    enum class Mode {
        DifficultyVsHashrate,
        TimeTrend
    };

    explicit MiniDiffHashChart(QWidget *parent = nullptr) : QWidget(parent) {
        setMinimumHeight(160);
    }

    void addSample(double difficulty, double hashrate) {
        if (difficulty <= 0.0 || hashrate < 0.0) return;
        samples_.append(QPointF(difficulty, hashrate));
        while (samples_.size() > 120) samples_.removeFirst();
        update();
    }

    void clearSamples() {
        samples_.clear();
        update();
    }

    bool hasSamples() const {
        return !samples_.isEmpty();
    }

    int sampleCount() const {
        return samples_.size();
    }

    void setMode(Mode mode) {
        mode_ = mode;
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing, true);
        p.fillRect(rect(), QColor(18, 22, 28));

        const int left = 52;
        const int right = 14;
        const int top = 12;
        const int bottom = 30;
        const QRect plot = rect().adjusted(left, top, -right, -bottom);
        if (!plot.isValid()) return;

        p.setPen(QColor(55, 65, 78));
        for (int i = 0; i <= 4; ++i) {
            const int y = plot.top() + (plot.height() * i) / 4;
            p.drawLine(plot.left(), y, plot.right(), y);
        }
        for (int i = 0; i <= 4; ++i) {
            const int x = plot.left() + (plot.width() * i) / 4;
            p.drawLine(x, plot.top(), x, plot.bottom());
        }

        p.setPen(QColor(130, 145, 165));
        p.drawRect(plot);

        if (samples_.isEmpty()) {
            p.setPen(QColor(175, 185, 200));
            p.drawText(plot, Qt::AlignCenter, "Waiting for live difficulty/hashrate samples...");
            p.drawText(8, plot.center().y(), "Hashrate");
            p.drawText(plot.center().x() - 28, rect().bottom() - 8, "Difficulty");
            return;
        }

        if (mode_ == Mode::DifficultyVsHashrate) {
            double minX = samples_.first().x();
            double maxX = samples_.first().x();
            double minY = samples_.first().y();
            double maxY = samples_.first().y();
            for (const QPointF &pt : samples_) {
                minX = std::min(minX, pt.x());
                maxX = std::max(maxX, pt.x());
                minY = std::min(minY, pt.y());
                maxY = std::max(maxY, pt.y());
            }

            const double padX = std::max((maxX - minX) * 0.08, 1e-9);
            const double padY = std::max((maxY - minY) * 0.08, 1e-9);
            minX -= padX;
            maxX += padX;
            minY -= padY;
            maxY += padY;

            QPolygonF poly;
            poly.reserve(samples_.size());
            for (const QPointF &pt : samples_) {
                const double nx = (pt.x() - minX) / (maxX - minX);
                const double ny = (pt.y() - minY) / (maxY - minY);
                const qreal px = plot.left() + nx * plot.width();
                const qreal py = plot.bottom() - ny * plot.height();
                poly.append(QPointF(px, py));
            }

            QVector<QPointF> sorted = samples_;
            std::sort(sorted.begin(), sorted.end(), [](const QPointF &a, const QPointF &b) {
                return a.x() < b.x();
            });

            QPolygonF trend;
            trend.reserve(sorted.size());
            const int n = static_cast<int>(sorted.size());
            for (int i = 0; i < n; ++i) {
                const int from = std::max(0, i - 2);
                const int to = std::min(n - 1, i + 2);
                double avgY = 0.0;
                for (int j = from; j <= to; ++j) avgY += sorted[j].y();
                avgY /= static_cast<double>(to - from + 1);

                const double nx = (sorted[i].x() - minX) / (maxX - minX);
                const double ny = (avgY - minY) / (maxY - minY);
                const qreal px = plot.left() + nx * plot.width();
                const qreal py = plot.bottom() - ny * plot.height();
                trend.append(QPointF(px, py));
            }

            p.setPen(QPen(QColor(86, 198, 255), 2.2));
            if (trend.size() >= 2) p.drawPolyline(trend);

            p.setBrush(QColor(255, 168, 76));
            p.setPen(Qt::NoPen);
            for (const QPointF &pt : poly) p.drawEllipse(pt, 3.0, 3.0);

            // Distinct axis colors in scatter mode: Y=cyan (hashrate), X=orange (difficulty).
            p.setPen(QPen(QColor(86, 198, 255), 1.6));
            p.drawLine(plot.left(), plot.top(), plot.left(), plot.bottom());
            p.setPen(QPen(QColor(255, 168, 76), 1.6));
            p.drawLine(plot.left(), plot.bottom(), plot.right(), plot.bottom());

            p.setPen(QColor(86, 198, 255));
            p.drawText(6, plot.top() + 6, formatHashrate(maxY));
            p.drawText(6, plot.bottom(), formatHashrate(minY));
            p.drawText(8, plot.center().y(), "Hashrate");

            p.setPen(QColor(255, 168, 76));
            p.drawText(plot.left(), rect().bottom() - 8, QString::number(minX, 'g', 6));
            p.drawText(plot.right() - 90, rect().bottom() - 8, QString::number(maxX, 'g', 6));
            p.drawText(plot.center().x() - 28, rect().bottom() - 8, "Difficulty");
            return;
        }

        double minDiff = samples_.first().x();
        double maxDiff = samples_.first().x();
        double minHash = samples_.first().y();
        double maxHash = samples_.first().y();
        for (const QPointF &pt : samples_) {
            minDiff = std::min(minDiff, pt.x());
            maxDiff = std::max(maxDiff, pt.x());
            minHash = std::min(minHash, pt.y());
            maxHash = std::max(maxHash, pt.y());
        }

        const double diffSpan = std::max(maxDiff - minDiff, 1e-9);
        const double hashSpan = std::max(maxHash - minHash, 1e-9);

        QPolygonF diffLine;
        QPolygonF hashLine;
        diffLine.reserve(samples_.size());
        hashLine.reserve(samples_.size());
        const int n = samples_.size();
        for (int i = 0; i < n; ++i) {
            const double nx = (n <= 1) ? 0.0 : static_cast<double>(i) / static_cast<double>(n - 1);
            const qreal px = plot.left() + nx * plot.width();

            const double diffNorm = (samples_[i].x() - minDiff) / diffSpan;
            const double hashNorm = (samples_[i].y() - minHash) / hashSpan;
            diffLine.append(QPointF(px, plot.bottom() - diffNorm * plot.height()));
            hashLine.append(QPointF(px, plot.bottom() - hashNorm * plot.height()));
        }

        p.setPen(QPen(QColor(255, 180, 70), 2.0));
        if (diffLine.size() >= 2) p.drawPolyline(diffLine);
        p.setPen(QPen(QColor(86, 198, 255), 2.0));
        if (hashLine.size() >= 2) p.drawPolyline(hashLine);

        p.setPen(QColor(175, 185, 200));
        p.drawText(6, plot.top() + 6, "Norm max");
        p.drawText(6, plot.bottom(), "Norm min");
        p.drawText(plot.left(), rect().bottom() - 8, "Old");
        p.drawText(plot.right() - 24, rect().bottom() - 8, "Now");

        p.setPen(QColor(255, 180, 70));
        p.drawText(plot.left() + 4, plot.top() + 16, "Difficulty");
        p.setPen(QColor(86, 198, 255));
        p.drawText(plot.left() + 4, plot.top() + 32, "Hashrate");
        p.setPen(QColor(175, 185, 200));
        p.drawText(plot.center().x() - 18, rect().bottom() - 8, "Time");
    }

private:
    Mode mode_ = Mode::DifficultyVsHashrate;
    QVector<QPointF> samples_;
};
}

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent) {
    setupUi();

    connect(connectBtn_, &QPushButton::clicked, this, [this]() {
        rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
        statusBar()->showMessage("RPC endpoint set. Loading chain data...");
        historicalSamplesLoaded_ = false;
        historicalSamplesLoading_ = false;
        if (diffHashChart_) {
            auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
            chart->clearSamples();
        }
        refreshOverview();
        refreshPeers();
        fetchRecordsLive();
        loadRecentBlocks();
    });

    connect(refreshBtn_, &QPushButton::clicked, this, &MainWindow::refreshOverview);
    connect(loadBlocksBtn_, &QPushButton::clicked, this, &MainWindow::loadRecentBlocks);
    connect(blockLookupBtn_, &QPushButton::clicked, this, &MainWindow::lookupBlock);
    connect(blockPrevBtn_, &QPushButton::clicked, this, [this]() { stepBlockHeight(-1); });
    connect(blockNextBtn_, &QPushButton::clicked, this, [this]() { stepBlockHeight(1); });
    connect(txLookupBtn_, &QPushButton::clicked, this, &MainWindow::lookupTransaction);
    connect(peersRefreshBtn_, &QPushButton::clicked, this, &MainWindow::refreshPeerWindow);
    connect(chartModeCombo_, &QComboBox::currentIndexChanged, this, [this](int idx) {
        if (!diffHashChart_) return;
        auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
        if (idx == 1) {
            chart->setMode(MiniDiffHashChart::Mode::TimeTrend);
        } else {
            chart->setMode(MiniDiffHashChart::Mode::DifficultyVsHashrate);
        }
    });
    connect(liveModeToggle_, &QCheckBox::toggled, this, [this](bool enabled) {
        if (!liveTimer_) return;
        if (enabled) {
            liveTimer_->start();
            pollLiveTip();
            statusBar()->showMessage("Live mode ON", 2000);
        } else {
            liveTimer_->stop();
            statusBar()->showMessage("Live mode OFF", 2000);
        }
    });

    connect(blocksTable_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int) {
                const QString hash = blocksTable_->item(row, 1)->data(Qt::UserRole).toString();
                blockLookupEdit_->setText(hash);
                lookupBlock();
            });
    connect(peersTable_, &QTableWidget::cellClicked, this, [this](int row, int) { showSelectedPeerDetails(row); });

    recordsTimer_ = new QTimer(this);
    recordsTimer_->setInterval(24 * 60 * 60 * 1000);
    connect(recordsTimer_, &QTimer::timeout, this, &MainWindow::fetchRecordsLive);
    recordsTimer_->start();

    liveTimer_ = new QTimer(this);
    liveTimer_->setInterval(7000);
    connect(liveTimer_, &QTimer::timeout, this, &MainWindow::pollLiveTip);
    liveTimer_->start();

    QTimer::singleShot(300, this, [this]() {
        rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
        refreshOverview();
        refreshPeers();
        refreshPeerWindow();
        fetchRecordsLive();
        loadRecentBlocks();
    });
}

void MainWindow::setupUi() {
    setWindowTitle("Gapcoin Blockchain Reader (Qt Add-on)");
    resize(1200, 780);

    QWidget *central = new QWidget(this);
    auto *root = new QVBoxLayout(central);

    auto *connBox = new QGroupBox("RPC Connection", central);
    auto *connGrid = new QGridLayout(connBox);
    urlEdit_ = new QLineEdit("http://127.0.0.1:31397", connBox);
    userEdit_ = new QLineEdit(connBox);
    passEdit_ = new QLineEdit(connBox);
    passEdit_->setEchoMode(QLineEdit::Password);
    connectBtn_ = new QPushButton("Connect", connBox);
    refreshBtn_ = new QPushButton("Refresh Overview", connBox);

    connGrid->addWidget(new QLabel("URL:"), 0, 0);
    connGrid->addWidget(urlEdit_, 0, 1);
    connGrid->addWidget(new QLabel("User:"), 0, 2);
    connGrid->addWidget(userEdit_, 0, 3);
    connGrid->addWidget(new QLabel("Pass:"), 0, 4);
    connGrid->addWidget(passEdit_, 0, 5);
    connGrid->addWidget(connectBtn_, 0, 6);
    connGrid->addWidget(refreshBtn_, 0, 7);
    liveModeToggle_ = new QCheckBox("Live", connBox);
    liveModeToggle_->setChecked(true);
    connGrid->addWidget(liveModeToggle_, 0, 8);
    connBox->setLayout(connGrid);

    auto *tabs = new QTabWidget(central);

    QWidget *overviewTab = new QWidget(tabs);
    auto *overviewLayout = new QVBoxLayout(overviewTab);

    auto *chainBox = new QGroupBox("Chain Overview", overviewTab);
    auto *chainForm = new QFormLayout(chainBox);
    chainValue_ = new QLabel("-");
    heightValue_ = new QLabel("-");
    headersValue_ = new QLabel("-");
    difficultyValue_ = new QLabel("-");
    networkSpeedValue_ = new QLabel("-");
    bestHashValue_ = new QLabel("-");
    progressValue_ = new QLabel("-");
    bestHashValue_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    chainForm->addRow("Chain", chainValue_);
    chainForm->addRow("Blocks", heightValue_);
    chainForm->addRow("Headers", headersValue_);
    chainForm->addRow("Difficulty", difficultyValue_);
    chainForm->addRow("Network Speed", networkSpeedValue_);
    chainForm->addRow("Best Hash", bestHashValue_);
    chainForm->addRow("Verification", progressValue_);
    peersOverviewValue_ = new QLabel("-");
    chainForm->addRow("Peers", peersOverviewValue_);
    recordsStatusValue_ = new QLabel("Not loaded");
    chainForm->addRow("Records", recordsStatusValue_);
    chartModeCombo_ = new QComboBox(chainBox);
    chartModeCombo_->addItem("Difficulty vs Hashrate");
    chartModeCombo_->addItem("Trend Through Time");
    chainForm->addRow("Graph Mode", chartModeCombo_);
    diffHashChart_ = new MiniDiffHashChart(chainBox);
    chainForm->addRow("Diff/Speed Graph", diffHashChart_);
    chainBox->setLayout(chainForm);

    auto *recentBox = new QGroupBox("Recent Blocks", overviewTab);
    auto *recentLayout = new QVBoxLayout(recentBox);

    auto *recentCtl = new QHBoxLayout();
    recentCount_ = new QSpinBox(recentBox);
    recentCount_->setRange(5, 200);
    recentCount_->setValue(25);
    loadBlocksBtn_ = new QPushButton("Load", recentBox);
    recentCtl->addWidget(new QLabel("Count:"));
    recentCtl->addWidget(recentCount_);
    recentCtl->addWidget(loadBlocksBtn_);
    recentCtl->addStretch(1);

    blocksTable_ = new QTableWidget(0, 7, recentBox);
    blocksTable_->setHorizontalHeaderLabels({"Height", "Hash", "Shift", "Merit", "Record", "Time", "Tx"});
    blocksTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    blocksTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    blocksTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    blocksTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    blocksTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    blocksTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    blocksTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    blocksTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    blocksTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    recentLayout->addLayout(recentCtl);
    recentLayout->addWidget(blocksTable_);
    recentBox->setLayout(recentLayout);

    overviewLayout->addWidget(chainBox);
    overviewLayout->addWidget(recentBox);

    QWidget *blockTab = new QWidget(tabs);
    auto *blockLayout = new QVBoxLayout(blockTab);
    auto *blockCtl = new QHBoxLayout();
    blockLookupEdit_ = new QLineEdit(blockTab);
    blockLookupEdit_->setPlaceholderText("Block hash or height");
    blockLookupBtn_ = new QPushButton("Lookup Block", blockTab);
    blockPrevBtn_ = new QPushButton("Height -", blockTab);
    blockNextBtn_ = new QPushButton("Height +", blockTab);
    blockCtl->addWidget(blockPrevBtn_);
    blockCtl->addWidget(blockNextBtn_);
    blockCtl->addWidget(blockLookupEdit_);
    blockCtl->addWidget(blockLookupBtn_);

    blockDetails_ = new QPlainTextEdit(blockTab);
    blockDetails_->setReadOnly(true);
    auto *blockFooter = new QHBoxLayout();
    peersBlockValue_ = new QLabel("Peers: -", blockTab);
    blockFooter->addStretch(1);
    blockFooter->addWidget(peersBlockValue_);
    blockLayout->addLayout(blockCtl);
    blockLayout->addWidget(blockDetails_);
    blockLayout->addLayout(blockFooter);

    QWidget *txTab = new QWidget(tabs);
    auto *txLayout = new QVBoxLayout(txTab);
    auto *txCtl = new QGridLayout();
    txidEdit_ = new QLineEdit(txTab);
    txBlockHashEdit_ = new QLineEdit(txTab);
    txBlockHashEdit_->setPlaceholderText("Blockhash (optional with txid; required if txid is empty)");
    txLookupBtn_ = new QPushButton("Lookup Tx", txTab);

    txCtl->addWidget(new QLabel("Txid:"), 0, 0);
    txCtl->addWidget(txidEdit_, 0, 1);
    txCtl->addWidget(new QLabel("Blockhash:"), 1, 0);
    txCtl->addWidget(txBlockHashEdit_, 1, 1);
    txCtl->addWidget(txLookupBtn_, 0, 2, 2, 1);

    txDetails_ = new QPlainTextEdit(txTab);
    txDetails_->setReadOnly(true);
    auto *txFooter = new QHBoxLayout();
    peersTxValue_ = new QLabel("Peers: -", txTab);
    txFooter->addStretch(1);
    txFooter->addWidget(peersTxValue_);
    txLayout->addLayout(txCtl);
    txLayout->addWidget(txDetails_);
    txLayout->addLayout(txFooter);

    QWidget *peersTab = new QWidget(tabs);
    auto *peersLayout = new QVBoxLayout(peersTab);
    auto *peersCtl = new QHBoxLayout();
    peersRefreshBtn_ = new QPushButton("Refresh Peers", peersTab);
    peersCtl->addWidget(peersRefreshBtn_);
    peersCtl->addStretch(1);

    peersTable_ = new QTableWidget(0, 10, peersTab);
    peersTable_->setHorizontalHeaderLabels({"Id", "Addr", "SubVer", "Ping", "Conn", "Synced H", "Synced B", "Recv", "Sent", "Ban"});
    peersTable_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    peersTable_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(7, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(8, QHeaderView::ResizeToContents);
    peersTable_->horizontalHeader()->setSectionResizeMode(9, QHeaderView::ResizeToContents);
    peersTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    peersTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);

    peerDetails_ = new QPlainTextEdit(peersTab);
    peerDetails_->setReadOnly(true);
    peerDetails_->setPlaceholderText("Select a peer row to view full details...");

    peersLayout->addLayout(peersCtl);
    peersLayout->addWidget(peersTable_);
    peersLayout->addWidget(peerDetails_);

    tabs->addTab(overviewTab, "Overview");
    tabs->addTab(blockTab, "Block");
    tabs->addTab(txTab, "Transaction");
    tabs->addTab(peersTab, "Peers");

    root->addWidget(connBox);
    root->addWidget(tabs, 1);
    setCentralWidget(central);
    statusBar()->showMessage("Live mode enabled: change RPC/auth and click Connect only when endpoint settings change");
}

void MainWindow::setBusy(bool busy) {
    busy_ = busy;
    connectBtn_->setEnabled(!busy);
    refreshBtn_->setEnabled(!busy);
    loadBlocksBtn_->setEnabled(!busy);
    blockLookupBtn_->setEnabled(!busy);
    txLookupBtn_->setEnabled(!busy);
    peersRefreshBtn_->setEnabled(!busy);
}

void MainWindow::showError(const QString &message) {
    statusBar()->showMessage(message, 8000);
    QMessageBox::warning(this, "RPC Error", message);
}

void MainWindow::refreshOverview() {
    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    setBusy(true);
    rpc_.call("getblockchaininfo", QJsonArray(),
              [this](const QJsonValue &result) {
                  const QJsonObject o = result.toObject();
                  chainValue_->setText(o.value("chain").toString("-"));
                  const int blocks = o.value("blocks").toInt(-1);
                  heightValue_->setText(QString::number(blocks));
                  if (blocks >= 0) lastKnownTip_ = blocks;
                  headersValue_->setText(QString::number(o.value("headers").toInt()));
                  const double fallbackDifficulty = o.value("difficulty").toDouble(-1.0);
                  difficultyValue_->setText(QString::number(fallbackDifficulty));
                  bestHashValue_->setText(o.value("bestblockhash").toString("-"));
                  progressValue_->setText(QString::number(o.value("verificationprogress").toDouble() * 100.0, 'f', 4) + "%");

                  rpc_.call("getdifficulty", QJsonArray(),
                            [this, fallbackDifficulty](const QJsonValue &diffResult) {
                                const double difficulty = diffResult.toDouble(fallbackDifficulty);
                                difficultyValue_->setText(QString::number(difficulty));

                                rpc_.call("getnetworkminingpower", QJsonArray(),
                                          [this, difficulty](const QJsonValue &powResult) {
                                              const double hps = powResult.toDouble(-1.0);
                                              networkSpeedValue_->setText(formatHashrate(hps));
                                              if (diffHashChart_ && difficulty > 0.0 && hps >= 0.0) {
                                                  auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
                                                  chart->addSample(difficulty, hps);
                                              }
                                          },
                                          [this, difficulty](const QString &) {
                                              rpc_.call("getnetworkhashps", QJsonArray(),
                                                        [this, difficulty](const QJsonValue &hashResult) {
                                                            const double hps = hashResult.toDouble(-1.0);
                                                            networkSpeedValue_->setText(formatHashrate(hps));
                                                            if (diffHashChart_ && difficulty > 0.0 && hps >= 0.0) {
                                                                auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
                                                                chart->addSample(difficulty, hps);
                                                            }
                                                        },
                                                        [this](const QString &) {
                                                            networkSpeedValue_->setText("n/a");
                                                        });
                                          });
                            },
                            [this, fallbackDifficulty](const QString &) {
                                rpc_.call("getnetworkminingpower", QJsonArray(),
                                          [this, fallbackDifficulty](const QJsonValue &powResult) {
                                              const double hps = powResult.toDouble(-1.0);
                                              networkSpeedValue_->setText(formatHashrate(hps));
                                              if (diffHashChart_ && fallbackDifficulty > 0.0 && hps >= 0.0) {
                                                  auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
                                                  chart->addSample(fallbackDifficulty, hps);
                                              }
                                          },
                                          [this, fallbackDifficulty](const QString &) {
                                              rpc_.call("getnetworkhashps", QJsonArray(),
                                                        [this, fallbackDifficulty](const QJsonValue &hashResult) {
                                                            const double hps = hashResult.toDouble(-1.0);
                                                            networkSpeedValue_->setText(formatHashrate(hps));
                                                            if (diffHashChart_ && fallbackDifficulty > 0.0 && hps >= 0.0) {
                                                                auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
                                                                chart->addSample(fallbackDifficulty, hps);
                                                            }
                                                        },
                                                        [this](const QString &) {
                                                            networkSpeedValue_->setText("n/a");
                                                        });
                                          });
                            });

                  loadHistoricalChartSamples();

                  refreshPeers();
                  refreshPeerWindow();
                  setBusy(false);
                  statusBar()->showMessage("Overview refreshed", 2500);
              },
              [this](const QString &err) {
                  setBusy(false);
                  showError(err);
              });
}

void MainWindow::loadRecentBlocks() {
    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    setBusy(true);
    blocksTable_->setRowCount(0);

    rpc_.call("getblockcount", QJsonArray(),
              [this](const QJsonValue &result) {
                  const int tip = result.toInt(-1);
                  if (tip < 0) {
                      setBusy(false);
                      showError("Invalid block count response.");
                      return;
                  }
                  fetchBlockByHeight(tip, recentCount_->value());
              },
              [this](const QString &err) {
                  setBusy(false);
                  showError(err);
              });
}

void MainWindow::fetchBlockByHeight(int height, int remaining) {
    if (remaining <= 0 || height < 0) {
        setBusy(false);
        statusBar()->showMessage("Recent blocks loaded", 2500);
        return;
    }

    rpc_.call("getblockhash", QJsonArray{height},
              [this, height, remaining](const QJsonValue &hashResult) {
                  const QString hash = hashResult.toString();
                  rpc_.call("getblock", QJsonArray{hash, 1},
                            [this, height, remaining](const QJsonValue &blockResult) {
                                const QJsonObject b = blockResult.toObject();

                                const int row = blocksTable_->rowCount();
                                blocksTable_->insertRow(row);

                                auto *h = new QTableWidgetItem(QString::number(height));
                                auto *hashItem = new QTableWidgetItem(shortHash(b.value("hash").toString()));
                                hashItem->setToolTip(b.value("hash").toString());
                                hashItem->setData(Qt::UserRole, b.value("hash").toString());
                                hashItem->setData(Qt::UserRole + 1, b);

                                const qint64 ts = b.value("time").toVariant().toLongLong();
                                const QString tsText = QDateTime::fromSecsSinceEpoch(ts).toString(Qt::ISODate);
                                auto *timeItem = new QTableWidgetItem(tsText);

                                const int shift = b.value("shift").toInt();
                                auto *shiftItem = new QTableWidgetItem(QString::number(shift));

                                const double merit = b.value("merit").toDouble();
                                auto *meritItem = new QTableWidgetItem(fixed4(merit));

                                const int gap = b.value("gaplen").toInt();
                                auto *recordItem = new QTableWidgetItem("-");

                                auto *txItem = new QTableWidgetItem(QString::number(b.value("nTx").toInt()));

                                blocksTable_->setItem(row, 0, h);
                                blocksTable_->setItem(row, 1, hashItem);
                                blocksTable_->setItem(row, 2, shiftItem);
                                blocksTable_->setItem(row, 3, meritItem);
                                blocksTable_->setItem(row, 4, recordItem);
                                blocksTable_->setItem(row, 5, timeItem);
                                blocksTable_->setItem(row, 6, txItem);

                                applyRecordBadge(row, gap, merit);

                                fetchBlockByHeight(height - 1, remaining - 1);
                            },
                            [this](const QString &err) {
                                setBusy(false);
                                showError(err);
                            });
              },
              [this](const QString &err) {
                  setBusy(false);
                  showError(err);
              });
}

void MainWindow::showBlockDetails(const QJsonObject &block) {
    blockDetails_->setPlainText(prettyJson(block));
    currentBlockHeight_ = block.value("height").toInt(-1);
}

void MainWindow::lookupBlock() {
    const QString query = blockLookupEdit_->text().trimmed();
    if (query.isEmpty()) {
        showError("Enter block hash or height.");
        return;
    }

    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    setBusy(true);

    bool isHeight = false;
    const int h = query.toInt(&isHeight);

    if (isHeight) {
        rpc_.call("getblockhash", QJsonArray{h},
                  [this](const QJsonValue &hashResult) {
                      const QString hash = hashResult.toString();
                      rpc_.call("getblock", QJsonArray{hash, 2},
                                [this](const QJsonValue &blockResult) {
                                    const QJsonObject block = blockResult.toObject();
                                    showBlockDetails(block);
                                    blockLookupEdit_->setText(QString::number(block.value("height").toInt()));
                                    refreshPeers();
                                    setBusy(false);
                                    statusBar()->showMessage("Block loaded", 2500);
                                },
                                [this](const QString &err) {
                                    setBusy(false);
                                    showError(err);
                                });
                  },
                  [this](const QString &err) {
                      setBusy(false);
                      showError(err);
                  });
        return;
    }

    rpc_.call("getblock", QJsonArray{query, 2},
              [this](const QJsonValue &blockResult) {
                  const QJsonObject block = blockResult.toObject();
                  showBlockDetails(block);
                  const int h = block.value("height").toInt(-1);
                  if (h >= 0) blockLookupEdit_->setText(QString::number(h));
                  refreshPeers();
                  setBusy(false);
                  statusBar()->showMessage("Block loaded", 2500);
              },
              [this](const QString &err) {
                  setBusy(false);
                  showError(err);
              });
}

void MainWindow::stepBlockHeight(int delta) {
    bool ok = false;
    int h = blockLookupEdit_->text().trimmed().toInt(&ok);
    if (!ok) h = currentBlockHeight_;
    if (h < 0) {
        showError("No known block height to step from. Load a block first.");
        return;
    }
    h = std::max(0, h + delta);
    blockLookupEdit_->setText(QString::number(h));
    lookupBlock();
}

void MainWindow::lookupTransaction() {
    const QString txid = txidEdit_->text().trimmed();
    const QString bh = txBlockHashEdit_->text().trimmed();

    if (txid.isEmpty() && bh.isEmpty()) {
        showError("Enter txid or blockhash.");
        return;
    }

    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    setBusy(true);

    if (txid.isEmpty()) {
        rpc_.call("getblock", QJsonArray{bh, 2},
                  [this](const QJsonValue &blockResult) {
                      const QJsonObject block = blockResult.toObject();
                      QJsonObject view;
                      view.insert("mode", "blockhash-only");
                      view.insert("hash", block.value("hash"));
                      view.insert("height", block.value("height"));
                      view.insert("confirmations", block.value("confirmations"));
                      view.insert("nTx", block.value("nTx"));
                      view.insert("tx", block.value("tx"));
                      txDetails_->setPlainText(prettyJson(view));
                      refreshPeers();
                      setBusy(false);
                      statusBar()->showMessage("Block transactions loaded", 2500);
                  },
                  [this](const QString &err) {
                      setBusy(false);
                      showError(err + "\n\nHint: provide a valid blockhash from Block/Overview tab.");
                  });
        return;
    }

    QJsonArray params;
    params.append(txid);
    params.append(true);
    if (!bh.isEmpty()) params.append(bh);

    rpc_.call("getrawtransaction", params,
              [this](const QJsonValue &txResult) {
                  txDetails_->setPlainText(prettyJson(txResult));
                  refreshPeers();
                  setBusy(false);
                  statusBar()->showMessage("Transaction loaded", 2500);
              },
              [this, bh](const QString &err) {
                  setBusy(false);
                  if (bh.isEmpty()) {
                      const bool maybeTxIndexIssue = err.contains("RPC error -5", Qt::CaseInsensitive)
                          || err.contains("No such mempool or blockchain transaction", Qt::CaseInsensitive)
                          || err.contains("txindex", Qt::CaseInsensitive);
                      if (maybeTxIndexIssue) {
                          showError(err + "\n\nHint: likely txindex is disabled. Enter the containing blockhash in the optional Blockhash field, then lookup again.");
                          return;
                      }
                  }
                  showError(err);
              });
}

void MainWindow::refreshPeers() {
    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());

    auto setPeersText = [this](const QString &text) {
        if (peersOverviewValue_) peersOverviewValue_->setText(text);
        if (peersBlockValue_) peersBlockValue_->setText(QString("Peers: %1").arg(text));
        if (peersTxValue_) peersTxValue_->setText(QString("Peers: %1").arg(text));
    };

    rpc_.call("getnetworkinfo", QJsonArray(),
              [setPeersText](const QJsonValue &result) {
                  const QJsonObject o = result.toObject();
                  if (o.contains("connections")) {
                      setPeersText(QString::number(o.value("connections").toInt()));
                      return;
                  }
                  setPeersText("n/a");
              },
              [this, setPeersText](const QString &) {
                  rpc_.call("getconnectioncount", QJsonArray(),
                            [setPeersText](const QJsonValue &result) {
                                setPeersText(QString::number(result.toInt()));
                            },
                            [setPeersText](const QString &) {
                                setPeersText("n/a");
                            });
              });
}

void MainWindow::refreshPeerWindow() {
    if (!peersTable_ || !peerDetails_) return;

    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    rpc_.call("getpeerinfo", QJsonArray(),
              [this](const QJsonValue &result) {
                  const QJsonArray peers = result.toArray();
                  peersTable_->setRowCount(0);
                  peerDetails_->clear();

                  for (int i = 0; i < peers.size(); ++i) {
                      const QJsonObject p = peers.at(i).toObject();
                      const int row = peersTable_->rowCount();
                      peersTable_->insertRow(row);

                      auto *idItem = new QTableWidgetItem(QString::number(p.value("id").toInt(-1)));
                      idItem->setData(Qt::UserRole, p);

                      peersTable_->setItem(row, 0, idItem);
                      peersTable_->setItem(row, 1, new QTableWidgetItem(p.value("addr").toString("-")));
                      peersTable_->setItem(row, 2, new QTableWidgetItem(p.value("subver").toString("-")));
                      peersTable_->setItem(row, 3, new QTableWidgetItem(QString::number(p.value("pingtime").toDouble(), 'f', 4)));
                      peersTable_->setItem(row, 4, new QTableWidgetItem(p.value("connection_type").toString("-")));
                      peersTable_->setItem(row, 5, new QTableWidgetItem(QString::number(p.value("synced_headers").toInt(-1))));
                      peersTable_->setItem(row, 6, new QTableWidgetItem(QString::number(p.value("synced_blocks").toInt(-1))));
                      peersTable_->setItem(row, 7, new QTableWidgetItem(QString::number(p.value("bytesrecv").toVariant().toLongLong())));
                      peersTable_->setItem(row, 8, new QTableWidgetItem(QString::number(p.value("bytessent").toVariant().toLongLong())));
                      peersTable_->setItem(row, 9, new QTableWidgetItem(QString::number(p.value("banscore").toInt(0))));
                  }

                  if (peersTable_->rowCount() > 0) {
                      peersTable_->selectRow(0);
                      showSelectedPeerDetails(0);
                  } else {
                      peerDetails_->setPlainText("No peers connected.");
                  }
              },
              [this](const QString &err) {
                  peersTable_->setRowCount(0);
                  peerDetails_->setPlainText(QString("Peers request failed:\n%1").arg(err));
              });
}

void MainWindow::showSelectedPeerDetails(int row) {
    if (!peersTable_ || !peerDetails_) return;
    if (row < 0 || row >= peersTable_->rowCount()) return;

    QTableWidgetItem *idItem = peersTable_->item(row, 0);
    if (!idItem) return;

    const QJsonObject peerObj = idItem->data(Qt::UserRole).toJsonObject();
    peerDetails_->setPlainText(prettyJson(peerObj));
}

void MainWindow::pollLiveTip() {
    if (busy_) return;

    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());
    rpc_.call("getblockcount", QJsonArray(),
              [this](const QJsonValue &result) {
                  const int tip = result.toInt(-1);
                  if (tip < 0) return;

                  if (lastKnownTip_ < 0) {
                      lastKnownTip_ = tip;
                      heightValue_->setText(QString::number(tip));
                      refreshPeers();
                      return;
                  }

                  if (tip != lastKnownTip_) {
                      lastKnownTip_ = tip;
                      refreshOverview();
                      loadRecentBlocks();
                      refreshPeerWindow();
                  } else {
                      heightValue_->setText(QString::number(tip));
                      refreshPeers();
                      refreshPeerWindow();
                  }
              },
              [this](const QString &) {
                  if (peersOverviewValue_) peersOverviewValue_->setText("n/a");
                  if (peersBlockValue_) peersBlockValue_->setText("Peers: n/a");
                  if (peersTxValue_) peersTxValue_->setText("Peers: n/a");
              });
}

void MainWindow::loadHistoricalChartSamples() {
    if (!diffHashChart_ || historicalSamplesLoaded_ || historicalSamplesLoading_) return;

    auto *chart = static_cast<MiniDiffHashChart *>(diffHashChart_);
    const int initialSamples = chart->sampleCount();

    historicalSamplesLoading_ = true;
    rpc_.setEndpoint(urlEdit_->text().trimmed(), userEdit_->text().trimmed(), passEdit_->text());

    rpc_.call("getblockcount", QJsonArray(),
              [this, chart, initialSamples](const QJsonValue &tipResult) {
                  const int tip = tipResult.toInt(-1);
                  if (tip < 0) {
                      historicalSamplesLoading_ = false;
                      return;
                  }

                  const int points = std::min(28, tip + 1);
                  if (points <= 0) {
                      historicalSamplesLoading_ = false;
                      return;
                  }

                  const int span = std::min(720, tip);
                  const int step = std::max(1, (points > 1) ? (span / (points - 1)) : 1);
                  const int start = std::max(0, tip - step * (points - 1));

                  QVector<int> heights;
                  heights.reserve(points);
                  for (int i = 0; i < points; ++i) {
                      heights.append(start + i * step);
                  }

                  auto fetchNext = std::make_shared<std::function<void(int)>>();
                  *fetchNext = [this, chart, heights, fetchNext, initialSamples](int idx) {
                      if (idx >= heights.size()) {
                          historicalSamplesLoading_ = false;
                          if (chart->sampleCount() > initialSamples) {
                              historicalSamplesLoaded_ = true;
                              statusBar()->showMessage("Historical difficulty/hashrate samples loaded", 2500);
                          } else {
                              statusBar()->showMessage("Historical samples unavailable from node RPC", 3500);
                          }
                          return;
                      }

                      const int h = heights[idx];
                      rpc_.call("getblockhash", QJsonArray{h},
                                [this, chart, h, idx, fetchNext](const QJsonValue &hashResult) {
                                    const QString hash = hashResult.toString();
                                    rpc_.call("getblock", QJsonArray{hash, 1},
                                              [this, chart, h, idx, fetchNext](const QJsonValue &blockResult) {
                                                  const QJsonObject block = blockResult.toObject();
                                                  const double diff = block.value("difficulty").toDouble(-1.0);

                                                  rpc_.call("getnetworkminingpower", QJsonArray{h},
                                                            [chart, diff, idx, fetchNext](const QJsonValue &powResult) {
                                                                const double hps = powResult.toDouble(-1.0);
                                                                if (diff > 0.0 && hps >= 0.0) {
                                                                    chart->addSample(diff, hps);
                                                                }
                                                                (*fetchNext)(idx + 1);
                                                            },
                                                            [this, chart, diff, h, idx, fetchNext](const QString &) {
                                                                rpc_.call("getnetworkminingpower", QJsonArray(),
                                                                          [chart, diff, idx, fetchNext](const QJsonValue &powResultNoArg) {
                                                                              const double hps = powResultNoArg.toDouble(-1.0);
                                                                              if (diff > 0.0 && hps >= 0.0) {
                                                                                  chart->addSample(diff, hps);
                                                                              }
                                                                              (*fetchNext)(idx + 1);
                                                                          },
                                                                          [this, chart, diff, h, idx, fetchNext](const QString &) {
                                                                              rpc_.call("getnetworkhashps", QJsonArray{120, h},
                                                                                        [chart, diff, idx, fetchNext](const QJsonValue &hashpsResult) {
                                                                                            const double hps = hashpsResult.toDouble(-1.0);
                                                                                            if (diff > 0.0 && hps >= 0.0) {
                                                                                                chart->addSample(diff, hps);
                                                                                            }
                                                                                            (*fetchNext)(idx + 1);
                                                                                        },
                                                                                        [idx, fetchNext](const QString &) {
                                                                                            (*fetchNext)(idx + 1);
                                                                                        });
                                                                          });
                                                            });
                                              },
                                              [idx, fetchNext](const QString &) {
                                                  (*fetchNext)(idx + 1);
                                              });
                                },
                                [idx, fetchNext](const QString &) {
                                    (*fetchNext)(idx + 1);
                                });
                  };

                  (*fetchNext)(0);
              },
              [this](const QString &) {
                  historicalSamplesLoading_ = false;
              });
}

void MainWindow::fetchRecordsLive() {
    QNetworkRequest req{QUrl(kRecordsUrl)};
    req.setHeader(QNetworkRequest::UserAgentHeader, "gapcoin-qt-blockchain-reader/1.0");

    QNetworkReply *reply = recordsNetwork_.get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QByteArray body = reply->readAll();
        if (reply->error() != QNetworkReply::NoError) {
            recordsStatusValue_->setText(QString("Fetch failed: %1").arg(reply->errorString()));
            reply->deleteLater();
            return;
        }

        QHash<int, double> records;
        const QList<QByteArray> lines = body.split('\n');
        for (const QByteArray &rawLine : lines) {
            const QByteArray line = rawLine.trimmed();
            if (line.isEmpty() || line.startsWith('#')) continue;
            const QList<QByteArray> parts = line.split(' ');
            QList<QByteArray> toks;
            for (const QByteArray &p : parts) {
                if (!p.isEmpty()) toks.push_back(p);
            }
            if (toks.size() < 2) continue;

            bool okGap = false;
            bool okMerit = false;
            const int gap = toks[0].toInt(&okGap);
            const double merit = toks[1].toDouble(&okMerit);
            if (!okGap || !okMerit) continue;

            if (!records.contains(gap)) {
                records.insert(gap, merit);
            }
        }

        recordMeritByGap_ = std::move(records);
        recordsStatusValue_->setText(QString("Loaded %1 gaps (live)").arg(recordMeritByGap_.size()));

        for (int row = 0; row < blocksTable_->rowCount(); ++row) {
            const QJsonObject b = blocksTable_->item(row, 1)->data(Qt::UserRole + 1).toJsonObject();
            const int gap = b.value("gaplen").toInt();
            const double merit = b.value("merit").toDouble();
            applyRecordBadge(row, gap, merit);
        }

        reply->deleteLater();
    });
}

void MainWindow::applyRecordBadge(int row, int gap, double merit) {
    QTableWidgetItem *recordItem = blocksTable_->item(row, 4);
    if (!recordItem) return;

    if (gap <= 0) {
        recordItem->setText("-");
        return;
    }

    if (!recordMeritByGap_.contains(gap)) {
        recordItem->setText("n/a");
        return;
    }

    const double rec = recordMeritByGap_.value(gap);
    const double delta = merit - rec;
    if (delta > 0.0) {
        recordItem->setText(QString("REC +%1").arg(fixed4(delta)));
    } else {
        recordItem->setText(QString("-%1").arg(fixed4(-delta)));
    }
}

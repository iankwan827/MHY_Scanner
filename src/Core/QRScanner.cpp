#include "QRScanner.h"

#define DETECT_PROTOTXT_PATH "./ScanModel/detect.prototxt"
#define DETECT_CAFFE_MODEL_PATH "./ScanModel/detect.caffemodel"
#define SR_PROTOTXT_PATH "./ScanModel/sr.prototxt"
#define SR_CAFFE_MODEL_PATH "./ScanModel/sr.caffemodel"

QRScanner::QRScanner()
{
    detector = cv::makePtr<cv::wechat_qrcode::WeChatQRCode>(DETECT_PROTOTXT_PATH, DETECT_CAFFE_MODEL_PATH,
                                                            SR_PROTOTXT_PATH, SR_CAFFE_MODEL_PATH);
    detector->setScaleFactor(0.4);
}

QRScanner::~QRScanner()
{
}

void QRScanner::decodeSingle(const cv::Mat& img, std::string& qrCode)
{
    // 计时：DNN 识别耗时（2026-10-11 DSH 修改）
    const ScanPerfTimer _t(1);
    const std::vector<std::string>& strDecoded = detector->detectAndDecode(img);
    if (strDecoded.size() > 0)
    {
        qrCode = strDecoded[0];
    }
}

void QRScanner::decodeMultiple(const cv::Mat& img, std::string& qrCode)
{
    const std::vector<std::string>& strDecoded = detector->detectAndDecode(img);
    for (int i = 0; i < strDecoded.size(); i++)
    {
        qrCode = strDecoded[i];
#ifdef _DEBUG
        std::cout << "decode:" << qrCode << std::endl;
#endif // DEBUG
    }
}
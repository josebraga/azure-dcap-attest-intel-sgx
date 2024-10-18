#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "vendor/json.hpp"

// Function to convert hex string to byte vector
std::vector<unsigned char> hexStringToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    size_t len = hex.length();
    bytes.reserve(len / 2);

    for (size_t i = 0; i < len; i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Function for Base64 encoding
std::string base64Encode(const std::vector<unsigned char>& buffer) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());

    // Disable newline
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer.data(), buffer.size());
    BIO_flush(bio);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encodedData(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encodedData;
}

// Callback function for libcurl to write response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*) userp)->append((char*) contents, size * nmemb);
    return size * nmemb;
}

// Function to send attestation request
bool sendAttestationRequest(
    const std::string& url,
    const std::string& encodedQuote,
    const std::string& encodedUserData,
    std::string& response) {
    std::cout << "Sending attestation request...\n";
    std::cout << "Quote: " << encodedQuote << '\n';
    std::cout << "User Data: " << encodedUserData << '\n';

    // Prepare JSON request body
    nlohmann::json requestBody;
    requestBody["quote"] = encodedQuote;
    requestBody["runtimeData"] = {
        {"data", encodedUserData},
        {"dataType", "Binary"}
    };
    std::string requestBodyStr = requestBody.dump();

    // Initialize CURL
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL." << std::endl;
        return false;
    }

    // Set CURL options
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBodyStr.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, requestBodyStr.size());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Set write callback
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // Perform the request
    CURLcode res = curl_easy_perform(curl);

    // Cleanup
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "CURL request failed: " << curl_easy_strerror(res) << std::endl;
        return false;
    }

    return true;
}

int main() {
    // Read the attestation URL from the environment variable
    const char* attestationUrlEnv = std::getenv("ATTESTATION_URL");
    if (!attestationUrlEnv) {
        std::cerr << "Environment variable ATTESTATION_URL is not set." << std::endl;
        return -1;
    }
    std::string attestationUrl = "https://" + std::string(attestationUrlEnv) + "/attest/SgxEnclave?api-version=2022-08-01";

    // Path to your JSON file
    std::string jsonFilename = "attestation_data.json";

    // Read and parse the JSON file
    std::ifstream jsonFile(jsonFilename);
    if (!jsonFile.is_open()) {
        std::cerr << "Failed to open JSON file: " << jsonFilename << std::endl;
        return -1;
    }

    nlohmann::json jsonData;
    try {
        jsonFile >> jsonData;
    } catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return -1;
    }

    // Extract "QuoteHex" and "EnclaveHeldDataHex"
    if (!jsonData.contains("QuoteHex") || !jsonData.contains("EnclaveHeldDataHex")) {
        std::cerr << "JSON does not contain required fields." << std::endl;
        return -1;
    }

    std::string quoteHex = jsonData["QuoteHex"];
    std::string enclaveHeldDataHex = jsonData["EnclaveHeldDataHex"];

    // Convert hex strings to byte vectors
    std::vector<unsigned char> quoteBytes = hexStringToBytes(quoteHex);
    std::vector<unsigned char> userDataBytes = hexStringToBytes(enclaveHeldDataHex);

    // Base64 encode the quote and user data
    std::string encodedQuote = base64Encode(quoteBytes);
    std::string encodedUserData = base64Encode(userDataBytes);

    // Azure Attestation Service endpoint

    // Send attestation request
    std::string response;
    bool success = sendAttestationRequest(attestationUrl, encodedQuote, encodedUserData, response);

    std::cout << "----------------------------------------\n";
    if (success) {
        std::cout << "Attestation response: " << response << '\n';
    } else {
        std::cerr << "Attestation request failed." << '\n';
        return -1;
    }

    return 0;
}


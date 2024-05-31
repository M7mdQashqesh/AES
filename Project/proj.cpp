// Name: Mohammed Qashqesh
// Id: 211014
// Project Description: AES Encryption Project 
// Dr.Mousa Farajallah 

#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <numeric>
#include <cmath>
#include <chrono>
#include <bitset>
#include <opencv2/opencv.hpp>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using namespace std;
using namespace chrono;
using namespace cv;
using namespace CryptoPP;

const int AES_KEYLENGTH = 16;
const int BLOCKSIZE = 16;

Mat readImageFromFile() {
	Mat image;
	string imagePath;
	bool loaded = false;

	while (!loaded) {
		// Read an image from file
		cout << "Enter the Image path: ";
		cin >> imagePath;

		// Attempt to load the image
		image = imread(imagePath, IMREAD_UNCHANGED);

		// Check if image was loaded
		if (image.empty()) {
			cerr << "Error: Unable to load image from file (Check the Path of Image)." << endl;
			system("pause");
			system("cls");
		}
		else {
			loaded = true;
		}
	}

	return image;
}

vector<unsigned char>createVector(Mat image) {

	// Get image dimensions
	int rows = image.rows;
	int cols = image.cols;
	int channels = image.channels();

	// Create the Vector of pixels of image 
	vector<unsigned char> pixelBytes(rows * cols * channels);

	if (channels == 1) {
		for (int y = 0; y < rows; ++y) {
			for (int x = 0; x < cols; ++x) {
				uchar pixel = image.at<uchar>(y, x);
				int index = (y * cols + x);
				pixelBytes[index] = pixel; // GrayScale
			}
		}
	}

	else if (channels == 3) {
		for (int y = 0; y < rows; ++y) {
			for (int x = 0; x < cols; ++x) {
				Vec3b pixel = image.at<Vec3b>(y, x);
				int index = (y * cols + x) * 3;
				pixelBytes[index] = pixel[0]; // Blue
				pixelBytes[index + 1] = pixel[1]; // Green
				pixelBytes[index + 2] = pixel[2]; // Red
			}
		}
	}
	
	return pixelBytes;
}

void openAndWriteFile(string fileName,const vector<unsigned char> nameOfVector ,Mat image) {
	// Open a file for writing
	ofstream outputFile(fileName);
	if (!outputFile.is_open()) {
		cerr << "Error: Could not open the output file" << endl;
	}
	else {
		if (image.channels() == 3) {
			// Write pixel byte values to the file
			for (int i = 0; i < image.rows * image.cols * 3; i += 3) {
				outputFile << static_cast<int>(nameOfVector[i + 2]) << " " << static_cast<int>(nameOfVector[i + 1]) << " " << static_cast<int>(nameOfVector[i]) << endl;
			}
		}
		else if (image.channels() == 1) {
			// Write pixel byte values to the file
			for (int i = 0; i < image.rows * image.cols; i++) {
				outputFile << static_cast<int>(nameOfVector[i]) << endl;
			}
		}

		// Close the file
		outputFile.close();
	}
}

vector<unsigned char> encryptData(vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv, double& encryptionTime) {
	// Start measuring time
	auto start = high_resolution_clock::now();

	// Prepare the AES encryption object with the provided key and IV
	AES::Encryption aesEncryption(key, AES_KEYLENGTH);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	vector<unsigned char> ciphertext;
	ArraySource(data.data(), data.size(), true,
		new StreamTransformationFilter(cbcEncryption,
			new VectorSink(ciphertext)
		)
	);

	// Stop measuring time
	auto finish = high_resolution_clock::now();

	duration<double> elapsedTime = finish - start;

	// Calculate encryption time in milliseconds
	encryptionTime = elapsedTime.count();

	cout << "The image is Encrypted" << endl;

	int padding = BLOCKSIZE - (ciphertext.size() % BLOCKSIZE);

	// Add the necessary padding zeros
	for (int i = 0; i < padding; ++i) {
		data.push_back(0x00);
	}

	// Return the encrypted data vector
	return ciphertext;
}

vector<unsigned char> decryptData(const vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv) {
	// Prepare the AES decryption object with the provided key and IV
	AES::Decryption aesDecryption(key, AES_KEYLENGTH);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	vector<unsigned char> decryptedData;
	ArraySource(ciphertext.data(), ciphertext.size(), true,
		new StreamTransformationFilter(cbcDecryption,
			new VectorSink(decryptedData)
		)
	);

	cout << "The image is Decrypted" << endl;

	// Return the decrypted data vector
	return decryptedData;
}


vector<unsigned char> encryptDataCase1(vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv, double& encryptionTime) {
	// Start measuring time
	auto start = high_resolution_clock::now();

	// Prepare the AES-CTR encryption object with the provided key and IV
	CTR_Mode<AES>::Encryption encryption;
	encryption.SetKeyWithIV(key, AES_KEYLENGTH, iv, BLOCKSIZE);

	vector<unsigned char> cipher(data.size());
	encryption.ProcessData(cipher.data(), data.data(), data.size());

	// Stop measuring time
	auto finish = high_resolution_clock::now();
	duration<double> elapsedTime = finish - start;

	// Calculate encryption time in milliseconds
	encryptionTime = elapsedTime.count(); // Convert to milliseconds

	cout << "The image is Encrypted" << endl;

	// Return the encrypted data vector
	return cipher;
}

// Function to decrypt data using AES-CTR
vector<unsigned char> decryptDataCase1(vector<unsigned char>& data, const unsigned char* key, const unsigned char* iv) {
	// Prepare the AES-CTR decryption object with the provided key and IV
	CTR_Mode<AES>::Decryption decryption;
	decryption.SetKeyWithIV(key, AES_KEYLENGTH, iv, BLOCKSIZE);

	vector<unsigned char> plain(data.size());
	decryption.ProcessData(plain.data(), data.data(), data.size());

	cout << "The image is Decrypted" << endl;

	// Return the decrypted data vector
	return plain;
}

double calculateNPCR( vector<unsigned char> vector1, vector<unsigned char> vector2) {
	// Ensure both vectors have the same size
	if (vector1.size() != vector2.size()) {
		cerr << "Error: Vectors must have the same size" << endl;
		return -1;
	}

	// Calculate the number of differing pixels
	int differingPixels = 0;
	int totalPixels = vector1.size();
	for (size_t i = 0; i < vector1.size(); ++i) {
		if (vector1[i] != vector2[i]) {
			++differingPixels;

		}
	}

	// Calculate NPCR
	double npcr = static_cast<double>(differingPixels) / totalPixels;

	return npcr;
}

double calculateUACI(vector<unsigned char> vector1, vector<unsigned char> vector2) {
	// Ensure both vectors have the same size
	if (vector1.size() != vector2.size()) {
		cerr << "Error: Vectors must have the same size" << endl;
		return -1;
	}

	// Calculate the sum of absolute differences
	double sum = 0.0;
	int totalPixels = vector1.size();
	for (size_t i = 0; i < vector1.size(); ++i) {
		sum += abs(vector1[i] - vector2[i]);

	}
	
	// Calculate UACI
	double uaci = sum / (255 * totalPixels);

	return uaci;
}

double calculateHD(vector<unsigned char> vector1, vector<unsigned char> vector2) {
	// Ensure both vectors have the same size
	if (vector1.size() != vector2.size()) {
		cerr << "Error: Vectors must have the same size" << endl;
		return -1;
	}

	// Calculate the Hamming Distance
	int differingBits = 0;
	int totalBits = vector1.size() * 8; // Assuming each element is a byte (8 bits)
	for (size_t i = 0; i < vector1.size(); ++i) {
		for (int bit = 0; bit < 8; ++bit) {
			unsigned char mask = 1 << bit;
			if ((vector1[i] & mask) != (vector2[i] & mask)) {
				++differingBits;
			}
		}

	}

	// Calculate HD
	double hd = static_cast<double>(differingBits) / totalBits;

	return hd;
}

vector<bool> stringToBits(const unsigned char key[], size_t bytesSize) {
	vector<bool> keyBits;

	// Calculate the size of the key array
	size_t keySize = bytesSize; // 16 bytes for a 128-bit key

	// Store each bit of each byte of the key in the vector
	for (size_t i = 0; i < keySize; ++i) {
		// Extract each bit from the byte and store it in the vector
		for (int j = 7; j >= 0; --j) {
			bool bit = (key[i] >> j) & 1;
			keyBits.push_back(bit);
		}
	}
	return keyBits;
}

void setKeyBit(vector<bool>& keyBits, int position, bool value) {
	keyBits[position] = value;
}

unsigned char* keyBitsToChar(vector<bool>& keyBits) {
	// Create a buffer to store the converted key
	unsigned char* key = new unsigned char[16];
	// Convert bits to bytes and store them in the key array
	for (size_t i = 0; i < 16; ++i) {
		key[i] = 0;
		for (int j = 0; j < 8; ++j) {
			key[i] |= keyBits[i * 8 + j] << (7 - j);
		}
	}
	return key;
}

vector<int> calculateHistogram(vector<unsigned char> vector1) {
	vector<int> histogram(256, 0); // Initialize histogram with zeros

	// Count occurrences of each pixel value
	for (unsigned char pixel : vector1) {
		histogram[pixel]++;
	}

	return histogram;
}

void drawHistogram(vector<int> histogram, string pathName) {
	// Find maximum count for scaling
	int maxCount = *max_element(histogram.begin(), histogram.end());

	// Create blank white image for histogram visualization
	Mat histImage(256, 256, CV_8UC3, Scalar(255, 255, 255));

	// Plot histogram
	for (int i = 0; i < 256; ++i) {
		// Normalize count to fit within image height
		int height = static_cast<int>(histogram[i] * 256 / maxCount);

		// Draw vertical line for each pixel value
		line(histImage, Point(i, 256), Point(i, 256 - height), Scalar(0, 0, 0));
	}

	// Display and save histogram image
	imshow(pathName, histImage);
	imwrite(pathName + ".png", histImage);
	waitKey(0);
}

double calculateChiSquare(vector<int> observedHistogram) {
	// Define expected histogram (uniform distribution)
	int totalPixels = 0;
	for (int count : observedHistogram) {
		totalPixels += count;
	}
	int numBins = observedHistogram.size();
	double expectedCount = totalPixels / numBins;

	// Calculate Chi-square statistic
	double chiSquare = 0;
	for (int observedCount : observedHistogram) {
		double deviation = observedCount - expectedCount;
		chiSquare += deviation * deviation / expectedCount;
	}

	return chiSquare;
}

Mat createImageFromVector(vector<unsigned char> pixelBytes, int cols, int rows, int channels, string outputPath) {

	Mat image(rows, cols, channels == 3 ? CV_8UC3 : CV_8UC1);

	int index = 0;
	for (int y = 0; y < rows; ++y) {
		for (int x = 0; x < cols; ++x) {
			if (channels == 3) {
				Vec3b& pixel = image.at<Vec3b>(y, x);
				pixel[0] = pixelBytes[index]; // Blue
				pixel[1] = pixelBytes[index + 1]; // Green
				pixel[2] = pixelBytes[index + 2]; // Red
				index += 3;
			}
			else if (channels == 1) {
				image.at<uchar>(y, x) = pixelBytes[index];
				++index;
			}
		}
	}

	// Save the image to file
	imwrite(outputPath, image);

	return image;
}

double calculateCorrelationCoefficient(vector<unsigned char> vector1, vector<unsigned char> vector2) {
	// Ensure both vectors have the same size
	if (vector1.size() != vector2.size()) {
		cerr << "Error: Vectors must have the same size" << endl;
		return -1;
	}

	// Calculate means
	double mean1 = accumulate(vector1.begin(), vector1.end(), 0.0) / vector1.size();
	double mean2 = accumulate(vector2.begin(), vector2.end(), 0.0) / vector2.size();

	// Calculate covariance and variances
	double cov = 0.0;
	double var1 = 0.0;
	double var2 = 0.0;

	for (size_t i = 0; i < vector1.size(); ++i) {
		cov += (vector1[i] - mean1) * (vector2[i] - mean2);
		var1 += pow(vector1[i] - mean1, 2);
		var2 += pow(vector2[i] - mean2, 2);
	}

	cov /= vector1.size();
	var1 /= vector1.size();
	var2 /= vector2.size();

	// Calculate correlation coefficient
	double correlationCoefficient = cov / sqrt(var1 * var2);

	return correlationCoefficient;
}

double calculateEntropy(vector<unsigned char> cipherVector) {
	// Count occurrences of each pixel value
	unordered_map<unsigned char, int> freqMap;
	for (unsigned char pixel : cipherVector) {
		freqMap[pixel]++;
	}

	// Calculate entropy
	double entropy = 0.0;
	int totalPixels = cipherVector.size();
	for (const auto& pair : freqMap) {
		double probability = static_cast<double>(pair.second) / totalPixels;
		entropy -= probability * log2(probability);
	}

	return entropy;
}

double calculateEncryptionQuality(vector<int> occurrencesP, vector<int> occurrencesC) {
	if (occurrencesP.size() != 256 || occurrencesC.size() != 256) {
		cerr << "Error: Occurrence vectors must be of size 256" << endl;
		return -1;
	}

	double eq = 0.0;
	for (int i = 0; i < 256; ++i) {
		eq += abs(occurrencesP[i] - occurrencesC[i]);
	}
	eq /= 256.0;
	return eq;
}

double timePerformance(vector<unsigned char> cipherImage, double encryptionTime) {
	if (encryptionTime == 0) {
		cout << "Error: Encryption time cannot be zero." << endl;
		return -1; // return an error code
	}

	return(cipherImage.size() / (encryptionTime / 1000));
}

double NCPB(double cpuSpeed, double ET) {
	if (ET == 0) {
		cout << "Error: ET per byte cannot be zero." << endl;
		return -1;
	}

	return cpuSpeed / ET;
}

void hideSecretBits(Mat& image, vector<bool> secretBits) {

	int totalPixels = image.rows * image.cols * image.channels();

	if (sizeof(secretBits) <= totalPixels) {
		int bitIndex = 0; // Index to iterate over secretBits
		for (int y = 0; y < image.rows; ++y) {
			for (int x = 0; x < image.cols; ++x) {
				for (int c = 0; c < image.channels(); ++c) {
					if (bitIndex < secretBits.size()) {
						// Get the current pixel value
						uchar& pixel = image.at<Vec3b>(y, x)[c];
						// Modify the least significant bit
						pixel = (pixel & 0xFE) | (secretBits[bitIndex] ? 1 : 0);
						++bitIndex;
					}
					else {
						cout << "Secret bits have been hidden within the image." << endl;
						cout << "The image containing confidential information has been saved." << endl;
						return; // Return if all secret bits are hidden
					}
				}
			}
		}
	}
	
	else {
		// Throw an exception or exit the program
		throw runtime_error("Insufficient space in the image to hide all secret bits\n");
	}

}

vector<bool> extractSecretBits(Mat& image, int numBits) {
	vector<bool> secretBits;
	int bitIndex = 0;

	for (int y = 0; y < image.rows; ++y) {
		for (int x = 0; x < image.cols; ++x) {
			for (int c = 0; c < image.channels(); ++c) {
				if (bitIndex < numBits) {
					uchar pixel = image.at<Vec3b>(y, x)[c];
					bool bit = pixel & 1;
					secretBits.push_back(bit);
					++bitIndex;
				}
				else {
					return secretBits;
				}
			}
		}
	}

	return secretBits;
}

string bitsToString(vector<bool> bits) {
	stringstream ss;
	for (size_t i = 0; i < bits.size(); i += 8) {
		unsigned char byte = 0;
		for (int j = 0; j < 8; ++j) {
			if (i + j < bits.size()) {
				byte |= bits[i + j] << (7 - j);
			}
		}
		ss << byte;
	}
	return ss.str();
}

int main() {

	const unsigned char key[] = "MohammedQashqesh";

	const unsigned char iv[] = "0123456789abcdef";

	double encryptionTime;

	const double cpuSpeed = 2600000000; // my cpu speed is 2.60Ghz

	cout << "Hello, this is an Image Encryption Program.\n"
		<< "You must add the image on which you will perform the operations\n";

	Mat image = readImageFromFile();

	int choice;
	do {

		system("cls");

		cout << "1) Encrypt and Decryption.\n"
			<< "2) Analysis test.\n"
			<< "3) Hiding confidential information.\n"
			<< "4) Extract confidential information.\n"
			<< "5) Exit Program.\n"
			<< "Select Your Choice: ";
		cin >> choice;

		switch (choice) {
		case 1: {

			system("cls");

			if (image.channels() == 1) {
				cout << "The Image is GreyScale.\n";
			}
			else if (image.channels() == 3) {
				cout << "The Image is Colored.\n";
			}

			vector<unsigned char> sharedVector;

			int case1Choice;
			do {
				cout << "1) AES Encryption.\n"
					<< "2) AES Decryption.\n"
					<< "3) Go Back.\n"
					<< "Select Your Choice: ";
				cin >> case1Choice;

				switch (case1Choice) {

				case 1: {

					vector<unsigned char> plainImage = createVector(image);

					Mat OriginalImage = createImageFromVector(plainImage, image.cols, image.rows, image.channels(), "OriginalImage.bmp");

					openAndWriteFile("Image.txt", plainImage, OriginalImage);

					// Display the image
					imshow("Original Image", OriginalImage);

					// Encrypt plain image
					vector<unsigned char> cipherImage = encryptDataCase1(plainImage, key, iv, encryptionTime);

					Mat EncryptedImage = createImageFromVector(cipherImage, image.cols, image.rows, image.channels(), "EncryptedImage.bmp");

					// Display the image
					imshow("Encrypted Image", EncryptedImage);

					// Wait for a keystroke in the window
					waitKey(0);

					system("pause");
					system("cls");
					break;
				}
				case 2: {
					Mat EncryptedImage = readImageFromFile();

					vector<unsigned char> cipherImage = createVector(EncryptedImage);

					// Decrypt cipher image
					vector<unsigned char> plainImage = decryptDataCase1(cipherImage, key, iv);

					Mat DecryptedImage = createImageFromVector(plainImage, image.cols, image.rows, image.channels(), "DecryptedImage.bmp");

					system("pause");
					system("cls");
					break;
				}
				case 3: {
					break;
				}
				default:
					cout << "invalid Choice!\n";
					system("pause");
					break;
				}

			} while (case1Choice != 3);

			break;
		}
		case 2: {

			system("cls");

			int case2Choice;
			do {
				cout << "1) Plain-text sensitivity attack.\n"
					<< "2) Key sensitivity attack.\n"
					<< "3) Go Back.\n"
					<< "Select Your Choice: ";
				cin >> case2Choice;

				switch (case2Choice) {
				case 1: {

					vector<unsigned char> originalPlainImage = createVector(image);

					vector<unsigned char> modifiedPlainImage = originalPlainImage;

					if (image.channels() == 1) {
						cout << "The Image is GreyScale.\n";

						cout << "The value of first Byte is= " << bitset<8>(static_cast<int>(modifiedPlainImage[0])) << endl;
						int num;

						while (true) {
							// Prompt the user to enter a new value to modify between 0-255
							cout << "Enter a new value one bit change to modify: ";
							string binaryInput;
							cin >> binaryInput;

							// Convert binary string to integer
							num = stoi(binaryInput, nullptr, 2);

							// Check if the entered value is within the valid range
							if (num >= 0 && num <= 255) {
								break; // Break the loop if the value is valid
							}
							else {
								cout << "Error: Entered value is not between 0-255. Please try again." << endl;
							}
						}

						modifiedPlainImage[0] = num;

						cout << "Modified value: " << bitset<8>(num) << endl;
					}

					else if (image.channels() == 3) {
						cout << "The Image is Colored.\n";

						cout << "The value of first Byte is= " << bitset<8>(static_cast<int>(modifiedPlainImage[2])) << endl;
						int num;

						while (true) {
							// Prompt the user to enter a new value to modify between 0-255
							cout << "Enter a new value one bit change to modify: ";
							string binaryInput;
							cin >> binaryInput;

							// Convert binary string to integer
							num = stoi(binaryInput, nullptr, 2);

							// Check if the entered value is within the valid range
							if (num >= 0 && num <= 255) {
								break; // Break the loop if the value is valid
							}
							else {
								cout << "Error: Entered value is not between 0-255. Please try again." << endl;
							}
						}

						modifiedPlainImage[2] = num;

						cout << "Modified value: " << bitset<8>(num) << endl;
					}

					vector<unsigned char>originalCipherImage = encryptData(originalPlainImage, key, iv, encryptionTime);
					cout << "The original image is encrypted." << endl;

					vector<unsigned char>modifiedCipherImage = encryptData(modifiedPlainImage, key, iv, encryptionTime);
					cout << "The modified image is encrypted." << endl;

					cout << "\n\t ----------------------------\n"
						<< "\t/\tAnalysis test\t    /\n"
						"\t----------------------------\n\n";

					// Calculate NPCR
					cout << "NPCR= " << calculateNPCR(originalCipherImage, modifiedCipherImage) * 100 << "%" << endl;

					// Calculate UACI
					cout << "UACI= " << calculateUACI(originalCipherImage, modifiedCipherImage) * 100 << "%" << endl;

					// Calculate HD
					cout << "HD= " << calculateHD(originalCipherImage, modifiedCipherImage) * 100 << "%" << endl;

					// Calculate histogram for Plain Image
					vector<int> histogramOfPlain = calculateHistogram(originalPlainImage);

					// Draw histogram
					drawHistogram(histogramOfPlain, "plainImageHistogram");

					// Calculate histogram for Cipher Image
					vector<int> histogramOfCipher = calculateHistogram(originalCipherImage);

					// Draw histogram
					drawHistogram(histogramOfCipher, "cipherImageHistogram");

					cout << "Chi-square statistic= " << calculateChiSquare(histogramOfCipher) << endl;

					// Calculate Correlation Analysis Test
					cout << "Correlation Analysis Test= " << calculateCorrelationCoefficient(originalPlainImage, originalCipherImage) << endl;

					// Calculate Entropy
					cout << "Entropy= " << calculateEntropy(originalCipherImage) << endl;

					// calculate Encryption quality 
					cout << "Encryption quality= " << calculateEncryptionQuality(calculateHistogram(originalPlainImage), calculateHistogram(originalCipherImage)) << endl;

					// calculate Encryption time
					cout << "Encryption Time= " << encryptionTime << " MilliSeconds" << endl;

					// Calculate Time Performance
					cout << "Time Performance= " << timePerformance(originalCipherImage, encryptionTime) << endl;

					// calculate number of cycle per byte
					cout << "Number Cycles Per Byte= " << NCPB(cpuSpeed, timePerformance(originalCipherImage, encryptionTime)) << endl;

					system("pause");
					system("cls");
					break;
				}
				case 2: {

					if (image.channels() == 1) {
						cout << "The Image is GreyScale.\n";
					}
					else if (image.channels() == 3) {
						cout << "The Image is Colored.\n";
					}

					vector<unsigned char> plainImage1 = createVector(image);

					vector<unsigned char> plainImage2 = createVector(image);

					// Convert key to bits
					vector<bool> originalKeyBits = stringToBits(key, 16);

					vector<bool> modifiedKeyBits = originalKeyBits;

					// Output key bits to the screen
					cout << "Key bits: ";
					for (bool bit : originalKeyBits) {
						cout << bit;
					}
					cout << endl;

					// Prompt user for bit position and new value
					int position = 127;
					bool value;
					cout << "Enter the new value (0 or 1), The change will happen on the last bit: ";
					cin >> value;

					// Change the specified bit in the key
					setKeyBit(modifiedKeyBits, position, value);

					// Output modified key bits to the screen
					cout << "Modified key bits: ";
					for (bool bit : modifiedKeyBits) {
						cout << bit;
					}
					cout << endl;

					// Convert modified key from bits back to unsigned char array
					unsigned char* modifiedKey = keyBitsToChar(modifiedKeyBits);

					vector<unsigned char>cipherImageByOriginalKey = encryptData(plainImage1, key, iv, encryptionTime);
					cout << "The image is encrypted by Original key." << endl;

					vector<unsigned char> cipherImageByModifiedKey = encryptData(plainImage2, modifiedKey, iv, encryptionTime);
					cout << "The image is encrypted by modified key." << endl;

					cout << "\n\t ----------------------------\n"
						<< "\t/\tAnalysis test\t    /\n"
						"\t----------------------------\n\n";

					// Calculate NPCR
					cout << "NPCR= " << calculateNPCR(cipherImageByOriginalKey, cipherImageByModifiedKey) * 100 << "%" << endl;

					// Calculate UACI
					cout << "UACI= " << calculateUACI(cipherImageByOriginalKey, cipherImageByModifiedKey) * 100 << "%" << endl;

					// Calculate HD
					cout << "HD= " << calculateHD(cipherImageByOriginalKey, cipherImageByModifiedKey) * 100 << "%" << endl;

					// Calculate histogram
					vector<int> histogramOfPlain = calculateHistogram(plainImage1);

					// Draw histogram
					drawHistogram(histogramOfPlain, "plainImageHistogramByKeySen");

					// Calculate histogram
					vector<int> histogramOfCipher = calculateHistogram(cipherImageByOriginalKey);

					// Draw histogram
					drawHistogram(histogramOfCipher, "cipherImageHistogramByKeySen");

					cout << "Chi-square statistic= " << calculateChiSquare(histogramOfCipher) << endl;

					// Calculate Correlation Analysis Test
					cout << "Correlation Analysis Test= " << calculateCorrelationCoefficient(plainImage1, cipherImageByOriginalKey) << endl;

					// Calculate Entropy
					cout << "Entropy= " << calculateEntropy(cipherImageByOriginalKey) << endl;

					// calculate Encryption quality 
					cout << "Encryption quality= " << calculateEncryptionQuality(calculateHistogram(plainImage1), calculateHistogram(cipherImageByOriginalKey)) << endl;

					// calculate Encryption time
					cout << "Encryption Time= " << encryptionTime << " MilliSeconds" << endl;

					// Calculate Time Performance
					cout << "Time Performance=" << timePerformance(cipherImageByOriginalKey, encryptionTime) << endl;

					// calculate number of cycle per byte
					cout << "Number Cycles Per Byte= " << NCPB(cpuSpeed, timePerformance(cipherImageByOriginalKey, encryptionTime)) << endl;

					system("pause");
					system("cls");
					break;
				}
				case 3: {
					break;
				}
				default:
					cout << "Invalid Choice!\n";
					system("pause");
					system("cls");
					break;
				}

			} while (case2Choice != 3);
			break;
		}
		case 3: {

			Mat imageWithSecret = image;

			cout << "Enter the secret Information (Without WhiteSpaces): ";
			string secretInput;
			cin >> secretInput;

			// Convert the secret key string to a C-style string (const unsigned char[])
			const unsigned char* secret = reinterpret_cast<const unsigned char*>(secretInput.c_str());

			size_t sizeOfSecret = 0;
			for (size_t i = 0; secret[i] != '\0'; ++i) {
				++sizeOfSecret;
			}

			cout << "Size of Secret Info is= " << sizeOfSecret << " Characters (" << sizeOfSecret * 8 << " bits)" << endl;

			vector<bool> secretBits = stringToBits(secret, sizeOfSecret);

			cout << "Secret bits: ";
			for (bool bit : secretBits) {
				cout << bit;
			}
			cout << endl;

			// Hide secret bits within the image
			hideSecretBits(imageWithSecret, secretBits);

			// Save the modified image
			imwrite("imageWithSecretInformation.bmp", imageWithSecret);

			vector<unsigned char>ImageWithSecret = createVector(imageWithSecret);

			openAndWriteFile("ImageWithSecret.txt", ImageWithSecret, imageWithSecret);

			system("pause");
			break;
		}
		case 4: {

			Mat imageWithSecret = readImageFromFile();

			cout << "Enter the number of bits to extract: ";
			int numBits;
			cin >> numBits;

			vector<bool> extractedBits = extractSecretBits(imageWithSecret, numBits);
			string extractedSecret = bitsToString(extractedBits);

			cout << "Extracted Secret: " << extractedSecret << endl;

			system("pause");
			break;
		}
		case 5: {
			cout << "Bye <3 \n";
			system("pause");
			break;
		}
		default: {
			cout << "Invalid Choice!\n";
			system("pause");
			break;
		}
		}
	} while (choice != 5);

	return 0;	
}
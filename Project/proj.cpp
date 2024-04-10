#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <opencv2/opencv.hpp>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using namespace std;
using namespace cv;
using namespace CryptoPP;

const int AES_KEYLENGTH = 128;

Mat readImageFromFile() {
	// Read an image from file
	string imagePath;
	cout << "Enter the Image path: ";
	cin >> imagePath;
	Mat image = imread(imagePath);

	return image;
}

vector<unsigned char>createVector(Mat image) {

	// Get image dimensions
	int rows = image.rows;
	int cols = image.cols;
	int channels = image.channels();

	// Create the Vector of pixels of image 
	vector<unsigned char> pixelBytes(rows * cols * channels);

	if (channels == 3) {
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

	else if (channels == 1) {
		for (int y = 0; y < rows; ++y) {
			for (int x = 0; x < cols; ++x) {
				uchar pixel = image.at<uchar>(y, x);
				int index = (y * cols + x);
				pixelBytes[index] = pixel; // GrayScale

			}
		}
	}
	
	return pixelBytes;
}

// Create and Write pixel byte values to the file
void openAndWriteFile(string& fileName,const vector<unsigned char>& nameOfVector ,Mat image) {
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

void encryptData(vector<unsigned char>& data, const unsigned char* key) {
	// Prepare the AES encryption object
	AES::Encryption aesEncryption(key, AES_KEYLENGTH / 8);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, key);

	// Encrypt the data
	string cipher;
	StringSource(data.data(), data.size(), true,
		new StreamTransformationFilter(cbcEncryption,
			new StringSink(cipher)
		) // StreamTransformationFilter
	); // StringSource

	// Copy the encrypted data back to the original data vector
	memcpy(data.data(), cipher.data(), data.size());
}

// Function to calculate NPCR (Normalized Pixel Change Rate)
double calculateNPCR(const vector<unsigned char>& vector1, const vector<unsigned char>& vector2) {
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

// Function to calculate UACI (Unified Average Changing Intensity)
double calculateUACI(const vector<unsigned char>& vector1, const vector<unsigned char>& vector2) {
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
	//
		// Calculate UACI
	double uaci = sum / (255 * totalPixels);

	return uaci;
}

// Function to calculate HD (Hamming Distance)
double calculateHD(const vector<unsigned char>& vector1, const vector<unsigned char>& vector2) {
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


vector<bool> getKeyBits(const unsigned char key[]) {
	vector<bool> keyBits;

	// Calculate the size of the key array
	size_t keySize = 16; // 16 bytes for a 128-bit key

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

unsigned char* keyBitsToChar(const vector<bool>& keyBits) {
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


// Function to calculate histogram of pixel values
vector<int> calculateHistogram(const vector<unsigned char>& vector1) {
	vector<int> histogram(256, 0); // Initialize histogram with zeros

	// Count occurrences of each pixel value
	for (unsigned char pixel : vector1) {
		histogram[pixel]++;
	}

	return histogram;
}

// Function to draw histogram
void drawHistogram(const vector<int>& histogram) {
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
	imshow("Histogram", histImage);
	imwrite("histogram_image.jpg", histImage);
	waitKey(0);
}

// Function to calculate Chi-square statistic
double calculateChiSquare(const vector<int>& observedHistogram) {
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

void saveEncryptedImage(Mat image,const vector<unsigned char>& vector1,const string& fileName) {

	// Create a new Mat object with the encrypted pixel values
	Mat encryptedImage(image.rows, image.cols, CV_8UC3);
	for (int y = 0; y < image.rows; y++) {
		for (int x = 0; x < image.cols; x++) {
			Vec3b& pixel = encryptedImage.at<Vec3b>(y, x);
			for (int c = 0; c < 3; c++) {
				pixel[c] = vector1[(y * image.cols + x) * 3 + c]; // Corrected index
			}
		}
	}

	// Save the encrypted image to a file
	imwrite(fileName + ".bmp", encryptedImage);

	cout << "Encrypted image has been saved as" << fileName << endl;

}



int main() {

		// Convert key to byte
	const unsigned char key[] = "211014"; // Replace "your_key_here" with your actual key

	cout << "Hello, this is an Image Encryption Program.\n"
		<< "You must add the image on which you will perform the operations\n";
	Mat image = readImageFromFile();

	// Check if the image was loaded successfully
	if (image.empty()) {
		cerr << "Error: Could not open or find the image" << endl;
		system("pause");
		return -1;
	}
	else if (image.empty() == false) {
		cout << "---------------------------------------------------------------------------------------------\n";

		int choice;
		do
		{
			cout << "1. Plain-text sensitivity attack.\n"
				<< "2. Key sensitivity attack.\n"
				<< "3. Exit.\n"
				<< "Selcet your Choice: ";
			cin >> choice;

			switch (choice) {
			case 1:{
				// Convert key to bits
				vector<bool> keyBits = getKeyBits(key);

				// Output key bits to the screen
				cout << "Key bits: ";
				for (bool bit : keyBits) {
					cout << bit;
				}
				cout << endl;

				if (image.channels() == 3) {
					cout << "The Image is Colored." << endl;

					// Create a vector to store bytes (RGB values) of each pixel
					vector<unsigned char> pixelBytes = createVector(image);

					string pixel_values = "pixel_values.txt"; // Replace with your file name
					openAndWriteFile(pixel_values, pixelBytes, image);
					cout << "Pixel values have been written to pixel_values.txt" << endl;

					// Create a new vector to store the modified pixel values
					vector<unsigned char> modifiedPixelBytes = pixelBytes;

					cout << "The value of first Byte is= " << static_cast<int>(pixelBytes[2]) << endl;
					cout << "enter a new value to modifie between 0-255 : ";
					int num;
					cin >> num;
					modifiedPixelBytes[2] = num;

					string modifiedPixel_values = "modifiedPixel_values.txt"; // Replace with your file name
					openAndWriteFile(modifiedPixel_values, modifiedPixelBytes, image);


					// Encrypt pixel bytes
					encryptData(pixelBytes, key);
					
					// Save the encrypted original image
					saveEncryptedImage(image, pixelBytes, "EncryptedOriginalImage");

					string encrypted_pixel_bytes = "encrypted_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_pixel_bytes, pixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_pixel_bytes.txt" << endl;


					// Encrypt modified pixel bytes
					encryptData(modifiedPixelBytes, key);

					// Save the encrypted modified image
					saveEncryptedImage(image, modifiedPixelBytes, "EncryptedModifiedImage");

					string encrypted_modified_pixel_bytes = "encrypted_modified_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_modified_pixel_bytes, modifiedPixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_modified_pixel_bytes.txt" << endl;

					// Calculate NPCR
					double npcr = calculateNPCR(pixelBytes, modifiedPixelBytes);
					// Output NPCR
					if (npcr != -1) {
						cout << "NPCR: " << npcr * 100 << "%" << endl;
					}

					// Calculate UACI
					double uaci = calculateUACI(pixelBytes, modifiedPixelBytes);
					// Output UACI
					if (uaci != -1) {
						cout << "UACI: " << uaci * 100 << "%" << endl;
					}

					// Calculate HD
					double hd = calculateHD(pixelBytes, modifiedPixelBytes);
					// Output HD
					if (hd != -1) {
						cout << "HD: " << hd * 100 << "%" << endl;
					}

					// Calculate histogram
					vector<int> histogram = calculateHistogram(pixelBytes);

					// Draw histogram
					drawHistogram(histogram);

					double chiSquare = calculateChiSquare(histogram);
					cout << "Chi-square statistic: " << chiSquare << endl;

				}

				else if (image.channels() == 1) {

					cout << "The Image is GreyScale." << endl;

					vector<unsigned char> pixelBytes = createVector(image);

					string pixel_values = "pixel_values.txt"; // Replace with your file name
					openAndWriteFile(pixel_values, pixelBytes, image);
					cout << "Pixel values have been written to pixel_values.txt" << endl;

					// Create a new vector to store the modified pixel values
					vector<unsigned char> modifiedPixelBytes = pixelBytes;
					cout << "enter a num between 0-255 : ";
					int num;
					cin >> num;
					modifiedPixelBytes[0] = num;

					string modifiedPixel_values = "modifiedPixel_values.txt"; // Replace with your file name
					openAndWriteFile(modifiedPixel_values, modifiedPixelBytes, image);

					// Encrypt pixel bytes
					encryptData(pixelBytes, key);

					string encrypted_pixel_bytes = "encrypted_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_pixel_bytes, pixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_pixel_bytes.txt" << endl;


					// Encrypt modified pixel bytes
					encryptData(modifiedPixelBytes, key);

					string encrypted_modified_pixel_bytes = "encrypted_modified_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_modified_pixel_bytes, modifiedPixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_modified_pixel_bytes.txt" << endl;


					// Calculate NPCR
					double npcr = calculateNPCR(pixelBytes, modifiedPixelBytes);
					// Output NPCR
					if (npcr != -1) {
						cout << "NPCR: " << npcr * 100 << "%" << endl;
					}

					// Calculate UACI
					double uaci = calculateUACI(pixelBytes, modifiedPixelBytes);
					// Output UACI
					if (uaci != -1) {
						cout << "UACI: " << uaci * 100 << "%" << endl;
					}

					// Calculate HD
					double hd = calculateHD(pixelBytes, modifiedPixelBytes);
					// Output HD
					if (hd != -1) {
						cout << "HD: " << hd * 100 << "%" << endl;
					}

					// Calculate histogram
					vector<int> histogram = calculateHistogram(pixelBytes);

					// Draw histogram
					drawHistogram(histogram);

					double chiSquare = calculateChiSquare(histogram);
					cout << "Chi-square statistic: " << chiSquare << endl;
				}
				system("pause");
				break;
			}

			case 2: {
				if (image.channels() == 3) {
					cout << "The Image is Colored." << endl;

					// Create a vector to store bytes (RGB values) of each pixel
					vector<unsigned char> pixelBytes = createVector(image);

					string pixel_values = "pixel_values.txt"; // Replace with your file name
					openAndWriteFile(pixel_values, pixelBytes, image);
					cout << "Pixel values have been written to pixel_values.txt" << endl;

					// Convert key to bits
					vector<bool> keyBits = getKeyBits(key);

					// Output key bits to the screen
					cout << "Key bits: ";
					for (bool bit : keyBits) {
						cout << bit;
					}
					cout << endl;

					// Create a copy vector to store the copy pixel values
					vector<unsigned char> copyPixelBytes = pixelBytes;

					// Prompt user for bit position and new value
					int position = 127;
					bool value;
					cout << "Enter the new value (0 or 1) for that bit: ";
					cin >> value;

					// Change the specified bit in the key
					setKeyBit(keyBits, position, value);

					// Output modified key bits to the screen
					cout << "Modified key bits: ";
					for (bool bit : keyBits) {
						cout << bit;
					}
					cout << endl;

					// Convert modified key from bits back to unsigned char array
					unsigned char* modifiedKey = keyBitsToChar(keyBits);

					// Output modified key as string
					cout << "Modified key: " << modifiedKey << endl;

					// Encrypt pixel bytes
					encryptData(pixelBytes, key);


					string encrypted_pixel_bytes = "encrypted_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_pixel_bytes, pixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_pixel_bytes.txt" << endl;

					string copyPixel_values = "copyPixel_values.txt"; // Replace with your file name
					openAndWriteFile(copyPixel_values, copyPixelBytes, image);

					// Encrypt pixel bytes
					encryptData(copyPixelBytes, modifiedKey);

					string encrypted_copy_pixel_bytes = "encrypted_copy_pixel_bytes.txt"; // Replace with your file name
					openAndWriteFile(encrypted_copy_pixel_bytes, copyPixelBytes, image);
					cout << "Encrypted pixel byte values have been written to encrypted_copy_pixel_bytes.txt" << endl;

					// Calculate NPCR
					double npcr = calculateNPCR(pixelBytes, copyPixelBytes);
					// Output NPCR
					if (npcr != -1) {
						cout << "NPCR: " << npcr * 100 << "%" << endl;
					}

					// Calculate UACI
					double uaci = calculateUACI(pixelBytes, copyPixelBytes);
					// Output UACI
					if (uaci != -1) {
						cout << "UACI: " << uaci * 100 << "%" << endl;
					}

					// Calculate HD
					double hd = calculateHD(pixelBytes, copyPixelBytes);
					// Output HD
					if (hd != -1) {
						cout << "HD: " << hd * 100 << "%" << endl;
					}

					// Calculate histogram
					vector<int> histogram = calculateHistogram(pixelBytes);

					// Draw histogram
					drawHistogram(histogram);

					double chiSquare = calculateChiSquare(histogram);
					cout << "Chi-square statistic: " << chiSquare << endl;

				}
				system("pause");
				break;
			}

			case 3:
				cout << "Exit the Program.\n";
				system("pause");
				break;
			default:
				cout << "Invalid Choice!\n";
				system("pause");
				break;
			}

			system("cls");
		} while (choice != 3);

			// Display the image
			// imshow("Image", image);

			// Wait for a keystroke in the window
			// waitKey(0);

		// End Program
		return 0;
	}
}
/*
    MIT License
    Author: Fred Kyung-jin Rezeau <fred@litemint.com>, 2024
    Permission is granted to use, copy, modify, and distribute this software for any purpose
    with or without fee.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
*/

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdlib>

#define CL_CALL(call)                                                               \
    do {                                                                            \
        cl_int err = call;                                                          \
        if (err != CL_SUCCESS) {                                                    \
            std::cout << "OpenCL Error in " << __FILE__ << ", line " << __LINE__    \
                      << ": Error Code " << err << std::endl;                       \
            exit(EXIT_FAILURE);                                                     \
        }                                                                           \
    } while (0)

void releaseResources(cl_context context, cl_command_queue commandQueue, cl_program program,
    cl_kernel kernel, cl_mem* buffers, int bufferCount) {
    for (int i = 0; i < bufferCount; i++) {
        if (buffers[i]) clReleaseMemObject(buffers[i]);
    }
    if (kernel) clReleaseKernel(kernel);
    if (program) clReleaseProgram(program);
    if (commandQueue) clReleaseCommandQueue(commandQueue);
    if (context) clReleaseContext(context);
}

static std::string getPlatform(cl_platform_id id) {
    size_t len = 0;
    CL_CALL(clGetPlatformInfo(id, CL_PLATFORM_NAME, 0, nullptr, &len));
    std::vector<char> buf(len);
    CL_CALL(clGetPlatformInfo(id, CL_PLATFORM_NAME, len, buf.data(), nullptr));
    return std::string(buf.data(), buf.data() + len - 1);
}

extern "C" int executeKernel(const char* platform, int deviceId, std::uint8_t* data, int dataSize, std::uint64_t startNonce, int nonceOffset, std::uint64_t batchSize,
    int difficulty, int threadsPerBlock, std::uint8_t* output, std::uint64_t* validNonce, bool showDeviceInfo) {
    cl_int error;
    cl_platform_id platformId = nullptr;
    cl_device_id selectedDevice = nullptr;
    cl_uint numDevices;
    cl_uint numPlatforms = 0;

    CL_CALL(clGetPlatformIDs(0, nullptr, &numPlatforms));
    std::vector<cl_platform_id> platforms(numPlatforms);
    CL_CALL(clGetPlatformIDs(numPlatforms, platforms.data(), nullptr));
    std::vector<std::string> platformNames;
    std::cout << "OpenCL platforms:" << std::endl;
    int platformIndex = -1;
    for (cl_uint i = 0; i < numPlatforms; ++i) {
        std::string name = getPlatform(platforms[i]);
        bool match = (platformIndex < 0 && platform && *platform && name == platform);
        if (match) platformIndex = static_cast<int>(i);
        std::cout << "    [" << (match ? "X" : " ") << "] " << name << std::endl;
    }
    platformId = platformIndex != -1 ? platforms[platformIndex] : platforms[0];

    CL_CALL(clGetDeviceIDs(platformId, CL_DEVICE_TYPE_GPU, 0, nullptr, &numDevices));

    if (deviceId >= numDevices) {
        std::cerr << "Invalid device ID" << std::endl;
        return -1;
    }

    std::vector<cl_device_id> devices(numDevices);
    CL_CALL(clGetDeviceIDs(platformId, CL_DEVICE_TYPE_GPU, numDevices, devices.data(), nullptr));
    selectedDevice = devices[deviceId];

    if (showDeviceInfo) {
        char deviceName[256];
        char deviceVersion[256];
        cl_uint computeUnits;
        size_t maxWorkGroupSize;
        size_t maxWorkItemSizes[3];
        cl_ulong globalMemSize;
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_NAME, sizeof(deviceName), deviceName, nullptr));
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_VERSION, sizeof(deviceVersion), deviceVersion, nullptr));
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(computeUnits), &computeUnits, nullptr));
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWorkGroupSize), &maxWorkGroupSize, nullptr));
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_MAX_WORK_ITEM_SIZES, sizeof(maxWorkItemSizes), &maxWorkItemSizes, nullptr));
        CL_CALL(clGetDeviceInfo(selectedDevice, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(globalMemSize), &globalMemSize, nullptr));
        std::cout << "Device: " << deviceName << " (" << deviceVersion << ")" << std::endl;
        std::cout << "Compute units: " << computeUnits << std::endl;
        std::cout << "Max work group size: " << maxWorkGroupSize << std::endl;
        std::cout << "Max work item sizes: [" 
                    << maxWorkItemSizes[0] << ", " 
                    << maxWorkItemSizes[1] << ", " 
                    << maxWorkItemSizes[2] << "]" << std::endl;
        std::cout << "Global memory size: " << (globalMemSize / (1024 * 1024)) << " MB" << std::endl;
    }

    cl_context context = clCreateContext(nullptr, 1, &selectedDevice, nullptr, nullptr, &error);
    if (!context) {
        std::cerr << "Error: " << error << std::endl;
        return -1;
    }
#if CL_TARGET_OPENCL_VERSION >= 200
    cl_command_queue commandQueue = clCreateCommandQueueWithProperties(context, selectedDevice, 0, &error);
#else
    cl_command_queue commandQueue = clCreateCommandQueue(context, selectedDevice, 0, &error);
#endif
    if (!commandQueue) {
        std::cerr << "Error: " << error << std::endl;
        releaseResources(context, commandQueue, nullptr, nullptr, nullptr, 0);
        return -1;
    }

    std::ifstream kernelFile("kernel.cl");
    std::ifstream keccakFile("utils/keccak.cl");
    if (!kernelFile.is_open() || !keccakFile.is_open()) {
        std::cerr << "Failed to load OpenCL kernel files." << std::endl;
        releaseResources(context, commandQueue, nullptr, nullptr, nullptr, 0);
        return -1;
    }
    std::string kernelSource((std::istreambuf_iterator<char>(kernelFile)), std::istreambuf_iterator<char>());
    std::string keccakSource((std::istreambuf_iterator<char>(keccakFile)), std::istreambuf_iterator<char>());
    kernelFile.close();
    keccakFile.close();
    std::string fullSource = keccakSource + "\n" + kernelSource;
    const char* sourceStr = fullSource.c_str();
    size_t sourceSize = fullSource.size();

    cl_program program = clCreateProgramWithSource(context, 1, &sourceStr, &sourceSize, &error);
    if (!program) {
        std::cerr << "Error: " << error << std::endl;
        releaseResources(context, commandQueue, program, nullptr, nullptr, 0);
        return -1;
    }
    std::string buildOptions = "-D CL_TARGET_OPENCL_VERSION=" + std::to_string(CL_TARGET_OPENCL_VERSION);
    error = clBuildProgram(program, 1, &selectedDevice, buildOptions.c_str(), nullptr, nullptr);
    if (error != CL_SUCCESS) {
        size_t logSize;
        clGetProgramBuildInfo(program, selectedDevice, CL_PROGRAM_BUILD_LOG, 0, NULL, &logSize);
        std::vector<char> buildLog(logSize);
        clGetProgramBuildInfo(program, selectedDevice, CL_PROGRAM_BUILD_LOG, logSize, buildLog.data(), NULL);
        std::cerr << "Kernel build error: " << std::endl << buildLog.data() << std::endl;
        releaseResources(context, commandQueue, program, nullptr, nullptr, 0);
        return -1;
    }
    cl_kernel kernel = clCreateKernel(program, "run", &error);
    if (!kernel || error != CL_SUCCESS) {
        std::cerr << "Error: " << error << std::endl;
        releaseResources(context, commandQueue, program, kernel, nullptr, 0);
        return -1;
    }

    cl_mem deviceDataBuffer = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, dataSize * sizeof(cl_uchar), data, &error);
    cl_mem foundBuffer = clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(cl_int), nullptr, &error);
    cl_mem outputBuffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32 * sizeof(cl_uchar), nullptr, &error);
    cl_mem validNonceBuffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(cl_ulong), nullptr, &error);
    cl_mem buffers[] = {deviceDataBuffer, foundBuffer, outputBuffer, validNonceBuffer};
    for (auto& buf : buffers) {
        if (!buf) {
            std::cerr << "Error allocating buffer." << std::endl;
            releaseResources(context, commandQueue, program, kernel, buffers, 4);
            return -1;
        }
    }
    cl_int foundValue = 0;
    error = clEnqueueWriteBuffer(commandQueue, foundBuffer, CL_TRUE, 0, sizeof(cl_int), &foundValue, 0, nullptr, nullptr);
    error |= clSetKernelArg(kernel, 0, sizeof(cl_int), &dataSize);
    error |= clSetKernelArg(kernel, 1, sizeof(cl_ulong), &startNonce);
    error |= clSetKernelArg(kernel, 2, sizeof(cl_int), &nonceOffset);
    error |= clSetKernelArg(kernel, 3, sizeof(cl_ulong), &batchSize);
    error |= clSetKernelArg(kernel, 4, sizeof(cl_int), &difficulty);
    error |= clSetKernelArg(kernel, 5, sizeof(cl_mem), &deviceDataBuffer);
    error |= clSetKernelArg(kernel, 6, sizeof(cl_mem), &foundBuffer);
    error |= clSetKernelArg(kernel, 7, sizeof(cl_mem), &outputBuffer);
    error |= clSetKernelArg(kernel, 8, sizeof(cl_mem), &validNonceBuffer);
    if (error != CL_SUCCESS) {
        std::cerr << "Error: " << error << std::endl;
        releaseResources(context, commandQueue, program, kernel, buffers, 4);
        return -1;
    }

    size_t maxWorkGroupSize;
    clGetDeviceInfo(selectedDevice, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(size_t), &maxWorkGroupSize, NULL);
    size_t localWorkSize = std::min(static_cast<size_t>(threadsPerBlock), maxWorkGroupSize);
    size_t globalWorkSize = ((batchSize + localWorkSize - 1) / localWorkSize) * localWorkSize;
    error = clEnqueueNDRangeKernel(commandQueue, kernel, 1, nullptr, &globalWorkSize, &localWorkSize, 0, nullptr, nullptr);
    if (error != CL_SUCCESS) {
        std::cerr << "Error: " << error << std::endl;
        releaseResources(context, commandQueue, program, kernel, buffers, 4);
        return -1;
    }

    clFinish(commandQueue);
    CL_CALL(clEnqueueReadBuffer(commandQueue, foundBuffer, CL_TRUE, 0, sizeof(cl_int), &foundValue, 0, nullptr, nullptr));
    if (foundValue == 1) {
        CL_CALL(clEnqueueReadBuffer(commandQueue, outputBuffer, CL_TRUE, 0, 32 * sizeof(cl_uchar), output, 0, nullptr, nullptr));
        CL_CALL(clEnqueueReadBuffer(commandQueue, validNonceBuffer, CL_TRUE, 0, sizeof(cl_ulong), validNonce, 0, nullptr, nullptr));
    }
    releaseResources(context, commandQueue, program, kernel, buffers, 4);
    return foundValue;
}

import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { Upload, File, AlertCircle } from 'lucide-react'

function FileUpload({ onFileSelect }) {
  const [selectedFile, setSelectedFile] = useState(null)

  const onDrop = useCallback((acceptedFiles) => {
    const file = acceptedFiles[0]
    if (file) {
      setSelectedFile(file)
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    accept: {
      'text/x-python': ['.py'],
      'application/x-msdownload': ['.exe', '.dll'],
      'application/x-javascript': ['.js'],
      'text/plain': ['.ps1', '.txt'],
    },
    maxFiles: 1,
    maxSize: 10 * 1024 * 1024, // 10MB
  })

  const handleAnalyze = () => {
    if (selectedFile) {
      onFileSelect(selectedFile)
    }
  }

  const handleRemove = () => {
    setSelectedFile(null)
  }

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  }

  return (
    <div className="space-y-6">
      {/* Dropzone */}
      <div
        {...getRootProps()}
        className={`
          relative border-2 border-dashed rounded-lg p-12 text-center cursor-pointer
          transition-all duration-200
          ${
            isDragActive
              ? 'border-blue-500 bg-blue-500/10'
              : 'border-gray-600 bg-gray-800/30 hover:border-blue-400 hover:bg-gray-800/50'
          }
        `}
      >
        <input {...getInputProps()} />
        <Upload className="w-16 h-16 mx-auto mb-4 text-gray-400" />
        
        {isDragActive ? (
          <div>
            <p className="text-xl font-semibold text-blue-400 mb-2">
              Drop file here
            </p>
            <p className="text-gray-400">
              Release to upload
            </p>
          </div>
        ) : (
          <div>
            <p className="text-xl font-semibold text-white mb-2">
              Drag & Drop File Here
            </p>
            <p className="text-gray-400 mb-4">
              or click to browse
            </p>
            <p className="text-sm text-gray-500">
              Supported: Python (.py), Executables (.exe, .dll), JavaScript (.js), PowerShell (.ps1)
            </p>
            <p className="text-sm text-gray-500 mt-1">
              Max file size: 10MB
            </p>
          </div>
        )}
      </div>

      {/* File Rejections */}
      {fileRejections.length > 0 && (
        <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-4">
          <div className="flex items-start">
            <AlertCircle className="w-5 h-5 text-red-400 mr-2 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-red-300 font-medium mb-1">File rejected:</p>
              {fileRejections.map(({ file, errors }) => (
                <div key={file.name} className="text-red-200 text-sm">
                  <p className="font-medium">{file.name}</p>
                  <ul className="list-disc list-inside mt-1">
                    {errors.map((e) => (
                      <li key={e.code}>{e.message}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Selected File */}
      {selectedFile && (
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-4 flex-1">
              <File className="w-10 h-10 text-blue-400 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <h3 className="text-lg font-semibold text-white truncate">
                  {selectedFile.name}
                </h3>
                <p className="text-sm text-gray-400">
                  Size: {formatFileSize(selectedFile.size)}
                </p>
                <p className="text-sm text-gray-400">
                  Type: {selectedFile.type || 'Unknown'}
                </p>
              </div>
            </div>
            <button
              onClick={handleRemove}
              className="ml-4 text-gray-400 hover:text-red-400 transition-colors"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          {/* Analyze Button */}
          <div className="mt-6">
            <button
              onClick={handleAnalyze}
              className="w-full py-3 px-6 bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white font-semibold rounded-lg transition-all duration-200 flex items-center justify-center space-x-2"
            >
              <Upload className="w-5 h-5" />
              <span>Analyze File for Malware</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

export default FileUpload

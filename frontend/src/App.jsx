import { useState } from 'react'
import { Upload, Shield, AlertTriangle, CheckCircle, Loader, FileCode } from 'lucide-react'
import FileUpload from './components/FileUpload'
import AnalysisResult from './components/AnalysisResult'
import Header from './components/Header'
import './index.css'

function App() {
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const handleFileUpload = async (file) => {
    setAnalyzing(true)
    setError(null)
    setResult(null)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Analysis failed')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      console.error('Analysis error:', err)
      setError(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const handleReset = () => {
    setResult(null)
    setError(null)
    setAnalyzing(false)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900">
      <Header />
      
      <main className="container mx-auto px-4 py-8 max-w-6xl">
        {/* Hero Section */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-blue-400 mr-4" />
            <h1 className="text-5xl font-bold text-white">
              ShadowHunter AI
            </h1>
          </div>
          <p className="text-xl text-gray-300 max-w-2xl mx-auto">
            First specialized platform for detecting AI-generated malware from ChatGPT, DeepSeek, and Claude
          </p>
        </div>

        {/* Main Content */}
        <div className="space-y-8">
          {!result && !analyzing && (
            <FileUpload onFileSelect={handleFileUpload} />
          )}

          {analyzing && (
            <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-12 text-center border border-blue-500/30">
              <Loader className="w-16 h-16 text-blue-400 mx-auto mb-4 animate-spin" />
              <h3 className="text-2xl font-semibold text-white mb-2">
                Analyzing File...
              </h3>
              <p className="text-gray-400">
                Running pattern detection, YARA scanning, and AI analysis
              </p>
              <div className="mt-6 max-w-md mx-auto">
                <div className="flex justify-between text-sm text-gray-400 mb-2">
                  <span>Progress</span>
                  <span>Analyzing...</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div className="bg-blue-500 h-2 rounded-full animate-pulse-slow" style={{width: '75%'}}></div>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-900/30 border border-red-500/50 rounded-lg p-6">
              <div className="flex items-start">
                <AlertTriangle className="w-6 h-6 text-red-400 mr-3 flex-shrink-0 mt-1" />
                <div className="flex-1">
                  <h3 className="text-lg font-semibold text-red-300 mb-1">
                    Analysis Failed
                  </h3>
                  <p className="text-red-200">{error}</p>
                  <button
                    onClick={handleReset}
                    className="mt-4 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
                  >
                    Try Again
                  </button>
                </div>
              </div>
            </div>
          )}

          {result && (
            <AnalysisResult result={result} onReset={handleReset} />
          )}
        </div>

        {/* Features Section */}
        {!result && !analyzing && (
          <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-gray-800/30 backdrop-blur-sm rounded-lg p-6 border border-gray-700/50">
              <FileCode className="w-10 h-10 text-blue-400 mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">
                Pattern Recognition
              </h3>
              <p className="text-gray-400 text-sm">
                Detects LLM-specific code signatures from DeepSeek, GPT-4, and Claude
              </p>
            </div>
            <div className="bg-gray-800/30 backdrop-blur-sm rounded-lg p-6 border border-gray-700/50">
              <Shield className="w-10 h-10 text-green-400 mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">
                YARA Scanning
              </h3>
              <p className="text-gray-400 text-sm">
                12+ custom rules for malware patterns and evasion techniques
              </p>
            </div>
            <div className="bg-gray-800/30 backdrop-blur-sm rounded-lg p-6 border border-gray-700/50">
              <CheckCircle className="w-10 h-10 text-purple-400 mb-3" />
              <h3 className="text-lg font-semibold text-white mb-2">
                GPU-Accelerated AI
              </h3>
              <p className="text-gray-400 text-sm">
                Deep semantic analysis using Gemma 2 9B on NVIDIA L4 GPUs
              </p>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="mt-16 py-6 border-t border-gray-800">
        <div className="container mx-auto px-4 text-center text-gray-500 text-sm">
          <p>Built with ❤️ for Cloud Run Hackathon 2025 - GPU Category</p>
          <p className="mt-1">Powered by Google Cloud Run + NVIDIA L4 GPU</p>
        </div>
      </footer>
    </div>
  )
}

export default App

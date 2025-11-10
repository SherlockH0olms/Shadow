import { Shield, AlertTriangle, CheckCircle, XCircle, TrendingUp, FileText } from 'lucide-react'

function AnalysisResult({ result, onReset }) {
  const isMalicious = result.is_malicious
  const confidencePercent = (result.confidence * 100).toFixed(1)

  const getRiskColor = (score) => {
    if (score >= 70) return 'text-red-400'
    if (score >= 40) return 'text-yellow-400'
    return 'text-green-400'
  }

  const getRiskBg = (score) => {
    if (score >= 70) return 'bg-red-500'
    if (score >= 40) return 'bg-yellow-500'
    return 'bg-green-500'
  }

  return (
    <div className="space-y-6">
      {/* Verdict Card */}
      <div className={`
        rounded-lg p-8 border-2
        ${isMalicious
          ? 'bg-red-900/30 border-red-500/50'
          : 'bg-green-900/30 border-green-500/50'
        }
      `}>
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-4">
            {isMalicious ? (
              <AlertTriangle className="w-16 h-16 text-red-400 flex-shrink-0" />
            ) : (
              <CheckCircle className="w-16 h-16 text-green-400 flex-shrink-0" />
            )}
            <div>
              <h2 className={`text-3xl font-bold mb-2 ${
                isMalicious ? 'text-red-300' : 'text-green-300'
              }`}>
                {isMalicious ? 'MALWARE DETECTED' : 'FILE APPEARS CLEAN'}
              </h2>
              <p className="text-lg text-gray-300 mb-4">
                File: <span className="font-mono">{result.file_name}</span>
              </p>
              <div className="flex items-center space-x-6 text-sm">
                <div>
                  <span className="text-gray-400">Confidence:</span>
                  <span className={`ml-2 font-bold ${
                    isMalicious ? 'text-red-300' : 'text-green-300'
                  }`}>
                    {confidencePercent}%
                  </span>
                </div>
                <div>
                  <span className="text-gray-400">Risk Score:</span>
                  <span className={`ml-2 font-bold ${getRiskColor(result.risk_score)}`}>
                    {result.risk_score}/100
                  </span>
                </div>
                {result.llm_source && result.llm_source !== 'unknown' && (
                  <div>
                    <span className="text-gray-400">LLM Source:</span>
                    <span className="ml-2 font-bold text-purple-300 uppercase">
                      {result.llm_source}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-6">
          <div className="flex justify-between text-sm text-gray-400 mb-2">
            <span>Risk Level</span>
            <span>{result.risk_score}/100</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-3">
            <div
              className={`h-3 rounded-full transition-all duration-500 ${getRiskBg(result.risk_score)}`}
              style={{ width: `${result.risk_score}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Detection Details */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Detected Patterns */}
        {result.detected_patterns && result.detected_patterns.length > 0 && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
            <div className="flex items-center mb-4">
              <Shield className="w-5 h-5 text-blue-400 mr-2" />
              <h3 className="text-lg font-semibold text-white">
                Detected Patterns ({result.detected_patterns.length})
              </h3>
            </div>
            <ul className="space-y-2">
              {result.detected_patterns.slice(0, 5).map((pattern, i) => (
                <li key={i} className="flex items-start text-sm">
                  <span className="text-blue-400 mr-2">•</span>
                  <span className="text-gray-300 font-mono">{pattern}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Evasion Techniques */}
        {result.evasion_techniques && result.evasion_techniques.length > 0 && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
            <div className="flex items-center mb-4">
              <AlertTriangle className="w-5 h-5 text-yellow-400 mr-2" />
              <h3 className="text-lg font-semibold text-white">
                Evasion Techniques ({result.evasion_techniques.length})
              </h3>
            </div>
            <ul className="space-y-2">
              {result.evasion_techniques.map((tech, i) => (
                <li key={i} className="flex items-start text-sm">
                  <span className="text-yellow-400 mr-2">⚠️</span>
                  <span className="text-gray-300">{tech}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Malicious Indicators */}
        {result.malicious_indicators && result.malicious_indicators.length > 0 && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
            <div className="flex items-center mb-4">
              <XCircle className="w-5 h-5 text-red-400 mr-2" />
              <h3 className="text-lg font-semibold text-white">
                Malicious Functions ({result.malicious_indicators.length})
              </h3>
            </div>
            <ul className="space-y-2">
              {result.malicious_indicators.map((func, i) => (
                <li key={i} className="flex items-start text-sm">
                  <span className="text-red-400 mr-2">✖️</span>
                  <span className="text-gray-300 font-mono">{func}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* YARA Matches */}
        {result.yara_matches && result.yara_matches.length > 0 && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
            <div className="flex items-center mb-4">
              <FileText className="w-5 h-5 text-purple-400 mr-2" />
              <h3 className="text-lg font-semibold text-white">
                YARA Rules ({result.yara_matches.length})
              </h3>
            </div>
            <ul className="space-y-2">
              {result.yara_matches.map((match, i) => (
                <li key={i} className="text-sm">
                  <div className="flex items-center">
                    <span className="text-purple-400 mr-2">✓</span>
                    <span className="text-white font-semibold">{match.rule}</span>
                  </div>
                  {match.meta && match.meta.description && (
                    <p className="text-gray-400 ml-5 mt-1 text-xs">
                      {match.meta.description}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* File Metadata */}
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6 border border-gray-700">
        <h3 className="text-lg font-semibold text-white mb-4">File Information</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-gray-400 mb-1">File Hash</p>
            <p className="text-gray-200 font-mono text-xs break-all">
              {result.file_hash.substring(0, 16)}...
            </p>
          </div>
          <div>
            <p className="text-gray-400 mb-1">File Size</p>
            <p className="text-gray-200">
              {(result.file_size / 1024).toFixed(2)} KB
            </p>
          </div>
          <div>
            <p className="text-gray-400 mb-1">Entropy</p>
            <p className="text-gray-200">
              {result.entropy || 'N/A'}
            </p>
          </div>
          <div>
            <p className="text-gray-400 mb-1">Obfuscation</p>
            <p className="text-gray-200 capitalize">
              {result.obfuscation_level || 'None'}
            </p>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-center">
        <button
          onClick={onReset}
          className="px-8 py-3 bg-gray-700 hover:bg-gray-600 text-white font-semibold rounded-lg transition-colors"
        >
          Analyze Another File
        </button>
      </div>
    </div>
  )
}

export default AnalysisResult

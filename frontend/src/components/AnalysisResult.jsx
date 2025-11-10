import { Shield, AlertTriangle, CheckCircle, XCircle, TrendingUp, FileText, Cpu, Binary } from 'lucide-react'

function AnalysisResult({ result, onReset }) {
  const isMalicious = result.is_malicious
  const confidencePercent = (result.confidence * 100).toFixed(1)
  const isBinaryAnalysis = result.analysis_type === 'binary_with_ghidra'

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
                File: <span className="font-mono">{result.file_name || result.filename}</span>
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
                {isBinaryAnalysis && (
                  <div>
                    <span className="text-cyan-400 font-semibold">🔬 Binary Analysis</span>
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

      {/* NEW: Ghidra Binary Analysis Section */}
      {isBinaryAnalysis && result.ghidra_summary && (
        <div className="bg-gradient-to-br from-cyan-900/30 to-blue-900/30 backdrop-blur-sm rounded-lg p-6 border border-cyan-500/30">
          <div className="flex items-center mb-4">
            <Binary className="w-6 h-6 text-cyan-400 mr-2" />
            <h3 className="text-xl font-bold text-white">
              Ghidra Reverse Engineering Analysis
            </h3>
          </div>
          
          {/* Summary Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-800/50 rounded-lg p-4 text-center">
              <p className="text-cyan-400 text-2xl font-bold">{result.ghidra_summary.total_functions}</p>
              <p className="text-gray-400 text-sm">Functions</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4 text-center">
              <p className="text-red-400 text-2xl font-bold">{result.ghidra_summary.suspicious_patterns_count}</p>
              <p className="text-gray-400 text-sm">Suspicious</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4 text-center">
              <p className="text-purple-400 text-2xl font-bold">{result.ghidra_summary.total_imports}</p>
              <p className="text-gray-400 text-sm">Imports</p>
            </div>
            <div className="bg-gray-800/50 rounded-lg p-4 text-center">
              <p className="text-yellow-400 text-2xl font-bold">{result.ghidra_summary.syscalls_detected}</p>
              <p className="text-gray-400 text-sm">Syscalls</p>
            </div>
          </div>

          {/* Critical Findings */}
          {result.ghidra_summary.risk_indicators && result.ghidra_summary.risk_indicators.length > 0 && (
            <div>
              <h4 className="text-white font-semibold mb-3">🚨 Critical Findings</h4>
              <ul className="space-y-2">
                {result.ghidra_summary.risk_indicators.map((finding, i) => (
                  <li key={i} className="flex items-start text-sm">
                    <span className="text-red-400 mr-2">▸</span>
                    <span className="text-gray-300">{finding}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Decompiled Code Preview */}
          {result.ghidra_analysis && result.ghidra_analysis.decompiled_code && result.ghidra_analysis.decompiled_code.length > 0 && (
            <div className="mt-6">
              <h4 className="text-white font-semibold mb-3">📄 Decompiled Functions</h4>
              {result.ghidra_analysis.decompiled_code.slice(0, 2).map((func, i) => (
                <div key={i} className="mb-4 bg-gray-900/50 rounded-lg p-4">
                  <p className="text-cyan-400 font-mono font-semibold mb-2">{func.function}()</p>
                  <pre className="text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">
                    {func.code.substring(0, 500)}
                    {func.code.length > 500 && '\n... [truncated]'}
                  </pre>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

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
        
        {isBinaryAnalysis && (
          <div className="mt-4 pt-4 border-t border-gray-700">
            <p className="text-sm text-cyan-400">
              <Cpu className="w-4 h-4 inline mr-1" />
              Advanced binary analysis performed with Ghidra reverse engineering
            </p>
          </div>
        )}
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

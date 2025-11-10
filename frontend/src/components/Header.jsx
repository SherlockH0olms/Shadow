import { Shield, Github } from 'lucide-react'

function Header() {
  return (
    <header className="bg-gray-900/50 backdrop-blur-sm border-b border-gray-800">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Shield className="w-8 h-8 text-blue-400" />
            <div>
              <h1 className="text-xl font-bold text-white">
                ShadowHunter AI
              </h1>
              <p className="text-xs text-gray-400">
                AI-Generated Malware Detection
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <a
              href="https://github.com/SherlockH0olms/Shadow"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center space-x-2 text-gray-300 hover:text-white transition-colors"
            >
              <Github className="w-5 h-5" />
              <span className="hidden md:inline text-sm">GitHub</span>
            </a>
            <div className="h-6 w-px bg-gray-700"></div>
            <div className="text-sm">
              <span className="text-gray-400">Status:</span>
              <span className="ml-2 text-green-400 font-semibold">Online</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header

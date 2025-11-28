import { useState } from 'react'
import { ChevronDownIcon, ChevronUpIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

export default function ResultsTable({ results, isLoading }) {
  const [sortColumn, setSortColumn] = useState(null)
  const [sortDirection, setSortDirection] = useState('asc')
  const [expandedRows, setExpandedRows] = useState(new Set())

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-4 border-mono-950 dark:border-mono-50 border-t-transparent"></div>
      </div>
    )
  }

  if (!results || !results.rows || results.rows.length === 0) {
    return (
      <div className="py-12 text-center text-mono-600 dark:text-mono-400">
        No results found
      </div>
    )
  }

  const { columns, rows } = results

  const handleSort = (columnName) => {
    if (sortColumn === columnName) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortColumn(columnName)
      setSortDirection('asc')
    }
  }

  const toggleRow = (index) => {
    const newExpanded = new Set(expandedRows)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedRows(newExpanded)
  }

  const exportCSV = () => {
    const csv = [
      columns.map((col) => col.name).join(','),
      ...rows.map((row) => row.join(',')),
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'query-results.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  const exportJSON = () => {
    const data = rows.map((row) => {
      const obj = {}
      columns.forEach((col, index) => {
        obj[col.name] = row[index]
      })
      return obj
    })

    const json = JSON.stringify(data, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'query-results.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  const isIPAddress = (value) => {
    return typeof value === 'string' && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)
  }

  const truncateValue = (value) => {
    const str = String(value)
    return str.length > 50 ? str.substring(0, 50) + '...' : str
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-mono-600 dark:text-mono-400">
          {results.row_count} {results.row_count === 1 ? 'result' : 'results'}
        </p>
        <div className="flex gap-2">
          <button
            onClick={exportCSV}
            className="flex items-center gap-1 rounded-lg px-3 py-1 text-sm text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            CSV
          </button>
          <button
            onClick={exportJSON}
            className="flex items-center gap-1 rounded-lg px-3 py-1 text-sm text-mono-700 dark:text-mono-300 hover:bg-mono-100 dark:hover:bg-mono-850 transition-colors"
          >
            <ArrowDownTrayIcon className="h-4 w-4" />
            JSON
          </button>
        </div>
      </div>

      <div className="overflow-x-auto rounded-lg border border-mono-200 dark:border-mono-800">
        <table className="min-w-full divide-y divide-mono-200 dark:divide-mono-800">
          <thead className="bg-mono-100 dark:bg-mono-850">
            <tr>
              <th className="w-8"></th>
              {columns.map((column) => (
                <th
                  key={column.name}
                  onClick={() => handleSort(column.name)}
                  className="cursor-pointer px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-mono-600 dark:text-mono-400 hover:bg-mono-150 dark:hover:bg-mono-800 transition-colors"
                >
                  <div className="flex items-center gap-2">
                    {column.name}
                    {sortColumn === column.name && (
                      sortDirection === 'asc' ? (
                        <ChevronUpIcon className="h-4 w-4" />
                      ) : (
                        <ChevronDownIcon className="h-4 w-4" />
                      )
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-mono-200 dark:divide-mono-800 bg-white dark:bg-mono-950">
            {rows.map((row, rowIndex) => (
              <>
                <tr
                  key={rowIndex}
                  className="hover:bg-mono-50 dark:hover:bg-mono-900 cursor-pointer transition-colors"
                  onClick={() => toggleRow(rowIndex)}
                >
                  <td className="px-2 py-4">
                    <button className="text-mono-400 dark:text-mono-600 hover:text-mono-600 dark:hover:text-mono-400 transition-colors">
                      {expandedRows.has(rowIndex) ? (
                        <ChevronUpIcon className="h-4 w-4" />
                      ) : (
                        <ChevronDownIcon className="h-4 w-4" />
                      )}
                    </button>
                  </td>
                  {row.map((cell, cellIndex) => (
                    <td
                      key={cellIndex}
                      className={clsx(
                        'px-6 py-4 text-sm',
                        isIPAddress(cell)
                          ? 'font-mono text-mono-800 dark:text-mono-200'
                          : 'text-mono-900 dark:text-mono-100'
                      )}
                    >
                      {truncateValue(cell)}
                    </td>
                  ))}
                </tr>
                {expandedRows.has(rowIndex) && (
                  <tr>
                    <td colSpan={columns.length + 1} className="bg-mono-100 dark:bg-mono-850 px-6 py-4">
                      <pre className="overflow-x-auto text-sm text-mono-900 dark:text-mono-100 font-mono">
                        {JSON.stringify(
                          columns.reduce((obj, col, idx) => {
                            obj[col.name] = row[idx]
                            return obj
                          }, {}),
                          null,
                          2
                        )}
                      </pre>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

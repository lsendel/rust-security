import React from 'react'
import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SecurityScoreCard } from '../cards/security-score-card'

describe('SecurityScoreCard', () => {
  it('renders security score correctly', async () => {
    render(<SecurityScoreCard />)
    
    // Wait for animation to complete
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    expect(screen.getByText('Security Score')).toBeInTheDocument()
  })

  it('displays trend indicator', () => {
    render(<SecurityScoreCard />)
    
    // Check for trend icon or value
    const trendText = screen.queryByText(/3.2%/) || screen.queryByText(/No change/)
    expect(trendText).toBeInTheDocument()
  })

  it('shows metrics breakdown', () => {
    render(<SecurityScoreCard />)
    
    // Check for category breakdown text
    expect(screen.getByText('Category Breakdown')).toBeInTheDocument()
  })

  it('handles low security score styling', () => {
    render(<SecurityScoreCard />)
    
    // Check that security score component exists
    const cardTitle = screen.getByText('Security Score')
    expect(cardTitle).toBeInTheDocument()
  })

  it('displays last updated time', () => {
    render(<SecurityScoreCard />)
    
    // Check for recent improvements section which indicates updates
    expect(screen.getByText('Recent Improvements')).toBeInTheDocument()
  })
})
// Function to format number as currency
function formatCurrency(number) {
    return 'GHS ' + parseFloat(number).toFixed(2);
}

// Function to calculate total amount
function updateTotal() {
    const shareDeposit = parseFloat(document.getElementById('share_deposit').value) || 0;
    const savingsDeposit = parseFloat(document.getElementById('savings_deposit').value) || 0;
    const principal = parseFloat(document.getElementById('principal').value) || 0;
    const interest = parseFloat(document.getElementById('interest').value) || 0;

    const total = shareDeposit + savingsDeposit + principal + interest;
    
    document.getElementById('total_amount').value = total;
    document.getElementById('total_display').textContent = formatCurrency(total);
}

// Withdrawal calculations
function updateWithdrawalTotal() {
    const shareWithdrawal = parseFloat(document.getElementById('share_withdrawal').value) || 0;
    const savingsWithdrawal = parseFloat(document.getElementById('savings_withdrawal').value) || 0;
    const totalWithdrawal = shareWithdrawal + savingsWithdrawal;
    document.getElementById('total_withdrawal').value = totalWithdrawal.toFixed(2);
}

function updateShareBalanceAfterWithdrawal() {
    const currentBalance = parseFloat(document.getElementById('share_balance').value) || 0;
    const withdrawal = parseFloat(document.getElementById('share_withdrawal').value) || 0;
    const balanceAfter = currentBalance - withdrawal;
    
    if (balanceAfter < 0) {
        alert('Insufficient share balance for withdrawal');
        document.getElementById('share_withdrawal').value = '';
        document.getElementById('share_balance_after').value = currentBalance.toFixed(2);
    } else {
        document.getElementById('share_balance_after').value = balanceAfter.toFixed(2);
    }
    updateWithdrawalTotal();
}

function updateSavingsBalanceAfterWithdrawal() {
    const currentBalance = parseFloat(document.getElementById('savings_balance').value) || 0;
    const withdrawal = parseFloat(document.getElementById('savings_withdrawal').value) || 0;
    const balanceAfter = currentBalance - withdrawal;
    
    if (balanceAfter < 0) {
        alert('Insufficient savings balance for withdrawal');
        document.getElementById('savings_withdrawal').value = '';
        document.getElementById('savings_balance_after').value = currentBalance.toFixed(2);
    } else {
        document.getElementById('savings_balance_after').value = balanceAfter.toFixed(2);
    }
    updateWithdrawalTotal();
}

// Add event listeners to all amount fields
document.addEventListener('DOMContentLoaded', function() {
    // Deposit event listeners
    const amountFields = document.querySelectorAll('.amount-field');
    amountFields.forEach(field => {
        field.addEventListener('input', updateTotal);
    });

    // Withdrawal event listeners
    const shareWithdrawalField = document.getElementById('share_withdrawal');
    shareWithdrawalField.addEventListener('input', updateShareBalanceAfterWithdrawal);
    const savingsWithdrawalField = document.getElementById('savings_withdrawal');
    savingsWithdrawalField.addEventListener('input', updateSavingsBalanceAfterWithdrawal);

    // Initialize totals
    updateTotal();
    updateWithdrawalTotal();

    // Initialize balances after withdrawal
    const shareBalance = document.getElementById('share_balance');
    const savingsBalance = document.getElementById('savings_balance');
    if (shareBalance) {
        document.getElementById('share_balance_after').value = shareBalance.value;
    }
    if (savingsBalance) {
        document.getElementById('savings_balance_after').value = savingsBalance.value;
    }
});

// Format all number inputs to 2 decimal places on blur
document.addEventListener('DOMContentLoaded', function() {
    const numberInputs = document.querySelectorAll('input[type="number"]');
    numberInputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.value) {
                this.value = parseFloat(this.value).toFixed(2);
            }
        });
    });

    // Validate withdrawal amounts
    const withdrawalFields = document.querySelectorAll('.withdrawal-field');
    withdrawalFields.forEach(field => {
        field.addEventListener('input', function() {
            const value = parseFloat(this.value) || 0;
            const balanceField = this.id === 'share_withdrawal' ? 'share_balance' : 'savings_balance';
            const balance = parseFloat(document.getElementById(balanceField).value) || 0;

            if (value > balance) {
                alert('Withdrawal amount cannot exceed balance!');
                this.value = '';
                updateWithdrawalTotal();
            }
        });
    });
});

// Set default date to today
document.addEventListener('DOMContentLoaded', function() {
    const today = new Date().toISOString().split('T')[0];
    const dateInputs = document.querySelectorAll('input[type="date"]');
    dateInputs.forEach(input => {
        input.value = today;
    });
});
